package frame

import (
	"encoding/binary"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// Multicast name-resolution ports.
const (
	MDNSPort  = 5353
	LLMNRPort = 5355
	NBNSPort  = 137
)

// NameAnswer is one host asserting that a name belongs to an address.
//
// The three protocols are merged because the attack is identical in all of
// them: a tool answers every name query on the segment with its own address, a
// Windows client believes it, connects, and hands over an authentication
// exchange. Which protocol carried the lie does not change what it was.
type NameAnswer struct {
	Proto string // "mdns", "llmnr" or "nbt-ns"
	Name  string
	Addr  netip.Addr
}

// ParseNameAnswers extracts the answers from a UDP payload for the given port.
//
// Only answers are returned. A query says nothing about ownership - every host
// asks about names it does not own, constantly - so counting queries would make
// every machine on the network look like a responder.
func ParseNameAnswers(port uint16, payload []byte) []NameAnswer {
	switch port {
	case MDNSPort:
		return parseDNSAnswers("mdns", payload)
	case LLMNRPort:
		return parseDNSAnswers("llmnr", payload)
	case NBNSPort:
		return parseNBNSAnswers(payload)
	}
	return nil
}

// parseDNSAnswers handles mDNS and LLMNR, which both use the DNS wire format.
//
// The parsing is delegated to x/net/dns/dnsmessage rather than hand-rolled.
// Compression pointers can be made to loop, and a hand-written walker that
// forgets to bound them is a denial of service in the one process that must
// keep running.
func parseDNSAnswers(proto string, payload []byte) []NameAnswer {
	var p dnsmessage.Parser
	h, err := p.Start(payload)
	if err != nil || !h.Response {
		return nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil
	}

	var out []NameAnswer
	for {
		ah, err := p.AnswerHeader()
		if err != nil {
			return out // includes ErrSectionDone
		}
		name := strings.TrimSuffix(ah.Name.String(), ".")
		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return out
			}
			out = append(out, NameAnswer{Proto: proto, Name: name, Addr: netip.AddrFrom4(r.A)})
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return out
			}
			out = append(out, NameAnswer{Proto: proto, Name: name, Addr: netip.AddrFrom16(r.AAAA)})
		default:
			if err := p.SkipAnswer(); err != nil {
				return out
			}
		}
	}
}

// NBT-NS layout: a DNS-like header, then a name encoded so that each nibble
// becomes a letter from 'A'. Responder speaks it heavily because older Windows
// still asks in it.
const (
	nbnsHeaderLen  = 12
	nbnsEncodedLen = 32
)

func parseNBNSAnswers(b []byte) []NameAnswer {
	if len(b) < nbnsHeaderLen {
		return nil
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	if flags&0x8000 == 0 {
		return nil // a query, not a response
	}
	answers := int(binary.BigEndian.Uint16(b[6:8]))
	if answers == 0 {
		return nil
	}

	i := nbnsHeaderLen
	var out []NameAnswer
	for a := 0; a < answers; a++ {
		// name: one length byte, then the encoded label, then a terminating
		// zero. Every read is bounded by the buffer, never by the length byte
		// on its own.
		if i >= len(b) {
			return out
		}
		l := int(b[i])
		if l != nbnsEncodedLen || i+1+l+1 > len(b) {
			return out
		}
		name := decodeNBNSName(b[i+1 : i+1+l])
		i += 1 + l + 1

		// type(2) class(2) ttl(4) rdlength(2)
		if i+10 > len(b) {
			return out
		}
		rdlen := int(binary.BigEndian.Uint16(b[i+8 : i+10]))
		i += 10
		if i+rdlen > len(b) {
			return out
		}
		// An NB record's data is flags(2) then the address.
		if rdlen >= 6 {
			out = append(out, NameAnswer{
				Proto: "nbt-ns",
				Name:  name,
				Addr:  netip.AddrFrom4([4]byte(b[i+2 : i+6])),
			})
		}
		i += rdlen
	}
	return out
}

// decodeNBNSName reverses the first-level encoding: each byte pair encodes one
// byte as two letters offset from 'A'.
func decodeNBNSName(enc []byte) string {
	var sb strings.Builder
	for i := 0; i+1 < len(enc); i += 2 {
		hi, lo := enc[i], enc[i+1]
		if hi < 'A' || hi > 'P' || lo < 'A' || lo > 'P' {
			break
		}
		sb.WriteByte((hi-'A')<<4 | (lo - 'A'))
	}
	s := sb.String()

	// A complete NetBIOS name decodes to exactly 16 bytes: 15 name characters
	// space-padded, plus one service-type byte. The service byte must be removed
	// POSITIONALLY, before trimming padding - it is commonly 0x00 (Workstation)
	// or 0x20 (Server), and both are in the padding cutset, so trimming first
	// would eat the service byte and then a real trailing character with it:
	// "FILESERVER\x20" would come back "FILESERVE". A short decode means the
	// encoding was not a valid name.
	if len(s) < 16 {
		return ""
	}
	return strings.TrimRight(s[:15], " \x00")
}
