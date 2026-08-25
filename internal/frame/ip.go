package frame

import (
	"encoding/binary"
	"net/netip"
)

// IP protocol numbers this package cares about.
const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58

	ip4MinHeader = 20
	ip6Header    = 40
	udpHeader    = 8
)

// IP is the parts of an IPv4 or IPv6 header the probes use. The two are merged
// deliberately: every caller wants "who sent this, to whom, carrying what", and
// nothing above this layer benefits from caring which version delivered it.
type IP struct {
	Version  int
	Src, Dst netip.Addr
	Proto    uint8
	// HopLimit is IPv4's TTL or IPv6's hop limit. A router advertisement that
	// did not come from the local segment can be spotted by it.
	HopLimit uint8
	Payload  []byte
}

// ParseIPv4 decodes an IPv4 header. Options are skipped via IHL.
func ParseIPv4(b []byte) (IP, bool) {
	if len(b) < ip4MinHeader {
		return IP{}, false
	}
	if b[0]>>4 != 4 {
		return IP{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	// A header shorter than the minimum is malformed; one longer than the
	// buffer would make the payload slice run off the end.
	if ihl < ip4MinHeader || ihl > len(b) {
		return IP{}, false
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	// Trust the smaller of the claimed length and what actually arrived.
	// Believing the header over the buffer is how a length field becomes a
	// read past the end.
	end := len(b)
	if total >= ihl && total < end {
		end = total
	}
	return IP{
		Version:  4,
		Src:      netip.AddrFrom4([4]byte(b[12:16])),
		Dst:      netip.AddrFrom4([4]byte(b[16:20])),
		Proto:    b[9],
		HopLimit: b[8],
		Payload:  b[ihl:end],
	}, true
}

// ParseIPv6 decodes an IPv6 header.
//
// Extension headers are not walked. Every message this watches for - router
// advertisements, DHCPv6, multicast name resolution - is sent without them, and
// walking a chain the sender controls is a loop an attacker gets to size.
func ParseIPv6(b []byte) (IP, bool) {
	if len(b) < ip6Header {
		return IP{}, false
	}
	if b[0]>>4 != 6 {
		return IP{}, false
	}
	payloadLen := int(binary.BigEndian.Uint16(b[4:6]))
	end := len(b)
	if got := ip6Header + payloadLen; payloadLen > 0 && got < end {
		end = got
	}
	return IP{
		Version:  6,
		Src:      netip.AddrFrom16([16]byte(b[8:24])).Unmap(),
		Dst:      netip.AddrFrom16([16]byte(b[24:40])).Unmap(),
		Proto:    b[6],
		HopLimit: b[7],
		Payload:  b[ip6Header:end],
	}, true
}

// UDP is a parsed datagram header.
type UDP struct {
	SrcPort, DstPort uint16
	Payload          []byte
}

// ParseUDP decodes a UDP header.
func ParseUDP(b []byte) (UDP, bool) {
	if len(b) < udpHeader {
		return UDP{}, false
	}
	length := int(binary.BigEndian.Uint16(b[4:6]))
	end := len(b)
	if length >= udpHeader && length < end {
		end = length
	}
	return UDP{
		SrcPort: binary.BigEndian.Uint16(b[0:2]),
		DstPort: binary.BigEndian.Uint16(b[2:4]),
		Payload: b[udpHeader:end],
	}, true
}

// Datagram is a fully decoded link-to-transport path, which is what every
// capture-fed probe actually wants.
type Datagram struct {
	Eth Ethernet
	IP  IP
	UDP UDP
}

// ParseUDPDatagram walks Ethernet -> IP -> UDP in one call, reporting false as
// soon as any layer is not what it claims. Probes use this rather than three
// nested parses so that no caller can forget one of the length checks.
func ParseUDPDatagram(b []byte) (Datagram, bool) {
	eth, ok := ParseEthernet(b)
	if !ok {
		return Datagram{}, false
	}
	var ip IP
	switch eth.EtherType {
	case EtherTypeIPv4:
		ip, ok = ParseIPv4(eth.Payload)
	case EtherTypeIPv6:
		ip, ok = ParseIPv6(eth.Payload)
	default:
		return Datagram{}, false
	}
	if !ok || ip.Proto != ProtoUDP {
		return Datagram{}, false
	}
	udp, ok := ParseUDP(ip.Payload)
	if !ok {
		return Datagram{}, false
	}
	return Datagram{Eth: eth, IP: ip, UDP: udp}, true
}
