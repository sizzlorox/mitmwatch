package frame

import (
	"encoding/binary"
	"net/netip"
	"strconv"
)

// ARP operations.
const (
	ARPRequest = 1
	ARPReply   = 2

	arpHTypeEthernet = 1
	// An Ethernet/IPv4 ARP body: htype, ptype, hlen, plen, op, then two
	// hardware/protocol address pairs.
	arpBodyLen = 8 + 2*(6+4)
)

// ARP is a parsed Ethernet/IPv4 ARP message.
//
// Only Ethernet-over-IPv4 is decoded. Other combinations exist but do not carry
// the attack this watches for, and accepting them would mean trusting attacker
// supplied hlen/plen to size reads.
type ARP struct {
	Op        uint16
	SenderMAC MAC
	SenderIP  netip.Addr
	TargetMAC MAC
	TargetIP  netip.Addr
}

// IsRequest and IsReply save callers from remembering the numbers.
func (a ARP) IsRequest() bool { return a.Op == ARPRequest }
func (a ARP) IsReply() bool   { return a.Op == ARPReply }

// IsGratuitous reports an unsolicited announcement: sender and target protocol
// addresses match, so the sender is telling the segment who owns an address
// nobody asked about.
//
// Legitimate hosts send these when an interface comes up or an address moves,
// and so does every ARP spoofer, continuously. Presence is not evidence;
// contradiction and frequency are.
func (a ARP) IsGratuitous() bool {
	return a.SenderIP.IsValid() && a.SenderIP == a.TargetIP
}

// IsProbe reports the address-availability check from RFC 5227: an all-zero
// sender address means "is anyone using this?", not "this is mine". Counting a
// probe as a claim would report every host that joins the network.
func (a ARP) IsProbe() bool {
	return !a.SenderIP.IsValid() || a.SenderIP.IsUnspecified()
}

// ParseARP decodes an ARP body. b is the Ethernet payload.
func ParseARP(b []byte) (ARP, bool) {
	if len(b) < arpBodyLen {
		return ARP{}, false
	}
	htype := binary.BigEndian.Uint16(b[0:2])
	ptype := binary.BigEndian.Uint16(b[2:4])
	hlen, plen := b[4], b[5]

	// Reject anything that is not Ethernet/IPv4 with the sizes those imply.
	// hlen and plen come off the wire; honouring them for other combinations
	// would mean letting the sender choose how far this reads.
	if htype != arpHTypeEthernet || ptype != EtherTypeIPv4 || hlen != 6 || plen != 4 {
		return ARP{}, false
	}

	var a ARP
	a.Op = binary.BigEndian.Uint16(b[6:8])
	copy(a.SenderMAC[:], b[8:14])
	a.SenderIP = netip.AddrFrom4([4]byte(b[14:18]))
	copy(a.TargetMAC[:], b[18:24])
	a.TargetIP = netip.AddrFrom4([4]byte(b[24:28]))
	return a, true
}

// OpName is for evidence a person reads.
func OpName(op uint16) string {
	switch op {
	case ARPRequest:
		return "request"
	case ARPReply:
		return "reply"
	}
	return "op " + strconv.FormatUint(uint64(op), 10)
}
