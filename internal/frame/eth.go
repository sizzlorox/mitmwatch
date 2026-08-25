package frame

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// EtherType values this package understands.
const (
	EtherTypeIPv4  = 0x0800
	EtherTypeARP   = 0x0806
	EtherTypeIPv6  = 0x86dd
	EtherTypeVLAN  = 0x8100
	EtherTypeQinQ  = 0x88a8
	etherHeaderLen = 14
	vlanTagLen     = 4
	// QinQ is two tags; more than that is not a real deployment.
	maxVLANTags = 2
)

// MAC is a hardware address in the same canonical form osq produces, so a MAC
// seen on the wire and a MAC read from a neighbour table compare as strings.
type MAC [6]byte

func (m MAC) String() string {
	var b strings.Builder
	b.Grow(17)
	const hex = "0123456789abcdef"
	for i, c := range m {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}

// IsZero reports the all-zero address, which is a placeholder rather than a
// device - notably the sender hardware address in an ARP probe.
func (m MAC) IsZero() bool {
	for _, c := range m {
		if c != 0 {
			return false
		}
	}
	return true
}

// IsBroadcast reports ff:ff:ff:ff:ff:ff.
func (m MAC) IsBroadcast() bool {
	for _, c := range m {
		if c != 0xff {
			return false
		}
	}
	return true
}

// IsLocallyAdministered reports the bit real hardware rarely sets and software
// pretending to be hardware often does.
func (m MAC) IsLocallyAdministered() bool { return m[0]&0x02 != 0 }

// OUI is the vendor prefix, formatted like the keys used for vendor lookup.
func (m MAC) OUI() string { return m.String()[:8] }

// Ethernet is a parsed link-layer header.
type Ethernet struct {
	Dst, Src  MAC
	EtherType uint16
	// VLAN is the outermost VLAN id, or 0 when the frame was untagged.
	VLAN uint16
	// Payload is the bytes after the header and any VLAN tags.
	Payload []byte
}

// ParseEthernet decodes a link-layer header.
//
// Every parser in this package is total: it validates length before every read,
// never panics, and reports failure rather than returning half-filled structs.
// These parse bytes an attacker chose, on a host whose job is to keep watching,
// so a malformed frame must cost one dropped packet and nothing else.
func ParseEthernet(b []byte) (Ethernet, bool) {
	if len(b) < etherHeaderLen {
		return Ethernet{}, false
	}
	var e Ethernet
	copy(e.Dst[:], b[0:6])
	copy(e.Src[:], b[6:12])
	e.EtherType = binary.BigEndian.Uint16(b[12:14])
	rest := b[etherHeaderLen:]

	// Walk VLAN tags. Stacked tags are legal - QinQ is two - so this is a loop
	// rather than a single check, but it is bounded: a frame claiming to be
	// nothing but tags is a frame built to spin this loop.
	for tags := 0; tags < maxVLANTags; tags++ {
		if e.EtherType != EtherTypeVLAN && e.EtherType != EtherTypeQinQ {
			break
		}
		if len(rest) < vlanTagLen {
			return Ethernet{}, false
		}
		if tags == 0 {
			e.VLAN = binary.BigEndian.Uint16(rest[0:2]) & 0x0fff
		}
		e.EtherType = binary.BigEndian.Uint16(rest[2:4])
		rest = rest[vlanTagLen:]
	}
	// Still a tag after the limit: reject rather than hand back a frame whose
	// EtherType says "VLAN" and whose Payload is therefore tag bytes, not a
	// protocol the caller can parse. Returning it would push the decision onto
	// every caller, and one of them would forget.
	if e.EtherType == EtherTypeVLAN || e.EtherType == EtherTypeQinQ {
		return Ethernet{}, false
	}
	e.Payload = rest
	return e, true
}

// EtherTypeName is for evidence a person reads.
func EtherTypeName(t uint16) string {
	switch t {
	case EtherTypeIPv4:
		return "IPv4"
	case EtherTypeARP:
		return "ARP"
	case EtherTypeIPv6:
		return "IPv6"
	}
	return "0x" + strconv.FormatUint(uint64(t), 16)
}
