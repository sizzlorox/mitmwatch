package frame

import (
	"encoding/binary"
	"net/netip"
)

// DHCPv4 ports and message types.
const (
	DHCPServerPort = 67
	DHCPClientPort = 68

	DHCPDiscover = 1
	DHCPOffer    = 2
	DHCPRequest  = 3
	DHCPDecline  = 4
	DHCPAck      = 5
	DHCPNak      = 6

	// Option codes. Only the ones that decide where a client sends its traffic
	// are decoded; the rest are skipped by length.
	optPad        = 0
	optSubnetMask = 1
	optRouter     = 3
	optDNS        = 6
	optMsgType    = 53
	optServerID   = 54
	optWPAD       = 252
	optEnd        = 255

	dhcpFixedLen = 236 // through the file field, before the magic cookie
)

var dhcpMagic = [4]byte{0x63, 0x82, 0x53, 0x63}

// DHCP is the part of a DHCPv4 message that decides where a client will send
// its traffic. That is the whole reason to watch it: a rogue server does not
// need to win every exchange, only to be believed once about the router or the
// resolver.
type DHCP struct {
	MsgType uint8
	// XID ties an offer back to the request that prompted it.
	XID uint32
	// YourIP is the address being handed out.
	YourIP netip.Addr
	// ServerID is who the server says it is (option 54), which is not always
	// the address the packet came from.
	ServerID netip.Addr
	Routers  []netip.Addr
	DNS      []netip.Addr
	// WPAD is option 252, a URL to a proxy configuration file. A client that
	// honours it sends everything through whatever the URL names.
	WPAD string
}

// MsgTypeName is for evidence a person reads.
func MsgTypeName(t uint8) string {
	switch t {
	case DHCPDiscover:
		return "DISCOVER"
	case DHCPOffer:
		return "OFFER"
	case DHCPRequest:
		return "REQUEST"
	case DHCPDecline:
		return "DECLINE"
	case DHCPAck:
		return "ACK"
	case DHCPNak:
		return "NAK"
	}
	return "type " + itoa(int(t))
}

// ParseDHCP decodes a DHCPv4 message from a UDP payload.
func ParseDHCP(b []byte) (DHCP, bool) {
	if len(b) < dhcpFixedLen+4 {
		return DHCP{}, false
	}
	if [4]byte(b[dhcpFixedLen:dhcpFixedLen+4]) != dhcpMagic {
		return DHCP{}, false
	}

	d := DHCP{
		XID:    binary.BigEndian.Uint32(b[4:8]),
		YourIP: netip.AddrFrom4([4]byte(b[16:20])),
	}

	// Options are a type-length-value list. Every read below is bounded by the
	// buffer, never by the length byte alone: the length is chosen by whoever
	// sent the packet, and a rogue DHCP server is precisely the sender this
	// parser exists to catch.
	opts := b[dhcpFixedLen+4:]
	for i := 0; i < len(opts); {
		code := opts[i]
		if code == optEnd {
			break
		}
		if code == optPad {
			i++
			continue
		}
		if i+2 > len(opts) {
			break
		}
		length := int(opts[i+1])
		start := i + 2
		if start+length > len(opts) {
			break // truncated option: stop rather than read past the end
		}
		val := opts[start : start+length]

		switch code {
		case optMsgType:
			if length >= 1 {
				d.MsgType = val[0]
			}
		case optServerID:
			if length >= 4 {
				d.ServerID = netip.AddrFrom4([4]byte(val[:4]))
			}
		case optRouter:
			d.Routers = append(d.Routers, addrsFrom(val)...)
		case optDNS:
			d.DNS = append(d.DNS, addrsFrom(val)...)
		case optWPAD:
			d.WPAD = string(val)
		case optSubnetMask:
			// decoded for completeness; not used by any rule yet
		}
		i = start + length
	}
	return d, true
}

// addrsFrom reads a run of IPv4 addresses, ignoring any trailing partial one.
func addrsFrom(b []byte) []netip.Addr {
	var out []netip.Addr
	for i := 0; i+4 <= len(b); i += 4 {
		out = append(out, netip.AddrFrom4([4]byte(b[i:i+4])))
	}
	return out
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
