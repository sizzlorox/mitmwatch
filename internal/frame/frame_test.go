package frame

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// buildARP assembles a real Ethernet+ARP frame the way a host would.
func buildARP(op uint16, senderMAC MAC, senderIP string, targetMAC MAC, targetIP string) []byte {
	var b bytes.Buffer
	b.Write(targetMAC[:])
	b.Write(senderMAC[:])
	binary.Write(&b, binary.BigEndian, uint16(EtherTypeARP)) //nolint:errcheck // bytes.Buffer

	binary.Write(&b, binary.BigEndian, uint16(arpHTypeEthernet)) //nolint:errcheck
	binary.Write(&b, binary.BigEndian, uint16(EtherTypeIPv4))    //nolint:errcheck
	b.WriteByte(6)
	b.WriteByte(4)
	binary.Write(&b, binary.BigEndian, op) //nolint:errcheck
	b.Write(senderMAC[:])
	sip := netip.MustParseAddr(senderIP).As4()
	b.Write(sip[:])
	b.Write(targetMAC[:])
	tip := netip.MustParseAddr(targetIP).As4()
	b.Write(tip[:])
	return b.Bytes()
}

var (
	router   = MAC{0x00, 0x11, 0x32, 0xc3, 0xcb, 0xd6}
	attacker = MAC{0xdc, 0xa6, 0x32, 0x11, 0x22, 0x33}
	bcast    = MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

func TestParseARPReply(t *testing.T) {
	raw := buildARP(ARPReply, router, "10.0.4.1", attacker, "10.0.4.48")
	eth, ok := ParseEthernet(raw)
	if !ok {
		t.Fatal("ethernet header rejected")
	}
	if eth.EtherType != EtherTypeARP {
		t.Fatalf("ethertype = %s, want ARP", EtherTypeName(eth.EtherType))
	}
	if eth.Src != router {
		t.Errorf("src = %s, want %s", eth.Src, router)
	}
	a, ok := ParseARP(eth.Payload)
	if !ok {
		t.Fatal("arp body rejected")
	}
	if !a.IsReply() {
		t.Error("not recognised as a reply")
	}
	if a.SenderIP.String() != "10.0.4.1" || a.SenderMAC != router {
		t.Errorf("sender = %s at %s", a.SenderIP, a.SenderMAC)
	}
	if a.TargetIP.String() != "10.0.4.48" {
		t.Errorf("target = %s", a.TargetIP)
	}
}

// The spoofer's signature: an unsolicited announcement claiming an address.
func TestGratuitousAndProbe(t *testing.T) {
	grat := buildARP(ARPReply, attacker, "10.0.4.1", bcast, "10.0.4.1")
	eth, _ := ParseEthernet(grat)
	a, ok := ParseARP(eth.Payload)
	if !ok {
		t.Fatal("rejected")
	}
	if !a.IsGratuitous() {
		t.Error("sender==target protocol address must read as gratuitous")
	}
	if a.IsProbe() {
		t.Error("a claim was misread as an availability probe")
	}

	// RFC 5227 probe: all-zero sender address means "is this free?", not "mine".
	// Counting it as a claim would report every host that joins the network.
	probe := buildARP(ARPRequest, attacker, "0.0.0.0", MAC{}, "10.0.4.77")
	eth2, _ := ParseEthernet(probe)
	p, ok := ParseARP(eth2.Payload)
	if !ok {
		t.Fatal("rejected")
	}
	if !p.IsProbe() {
		t.Error("an address-availability probe must not read as a claim")
	}
}

func TestVLANTaggedFrameIsUnwrapped(t *testing.T) {
	inner := buildARP(ARPReply, router, "10.0.4.1", attacker, "10.0.4.48")
	var b bytes.Buffer
	b.Write(inner[0:12])                                      // dst + src
	binary.Write(&b, binary.BigEndian, uint16(EtherTypeVLAN)) //nolint:errcheck
	binary.Write(&b, binary.BigEndian, uint16(0x0064))        // vlan 100
	binary.Write(&b, binary.BigEndian, uint16(EtherTypeARP))  //nolint:errcheck
	b.Write(inner[14:])

	eth, ok := ParseEthernet(b.Bytes())
	if !ok {
		t.Fatal("tagged frame rejected")
	}
	if eth.VLAN != 100 {
		t.Errorf("vlan = %d, want 100", eth.VLAN)
	}
	if eth.EtherType != EtherTypeARP {
		t.Errorf("ethertype after untagging = %s", EtherTypeName(eth.EtherType))
	}
	if _, ok := ParseARP(eth.Payload); !ok {
		t.Error("arp body lost when the vlan tag was stripped")
	}
}

// Only Ethernet/IPv4 is decoded. Honouring an attacker-supplied hlen/plen for
// other combinations would mean letting the sender choose how far we read.
func TestNonEthernetIPv4ARPIsRejected(t *testing.T) {
	raw := buildARP(ARPReply, router, "10.0.4.1", attacker, "10.0.4.48")
	eth, _ := ParseEthernet(raw)
	for name, mut := range map[string]func([]byte){
		"hardware type not ethernet": func(p []byte) { binary.BigEndian.PutUint16(p[0:2], 99) },
		"protocol type not ipv4":     func(p []byte) { binary.BigEndian.PutUint16(p[2:4], EtherTypeIPv6) },
		"hardware length not 6":      func(p []byte) { p[4] = 8 },
		"protocol length not 4":      func(p []byte) { p[5] = 16 },
	} {
		payload := append([]byte(nil), eth.Payload...)
		mut(payload)
		if _, ok := ParseARP(payload); ok {
			t.Errorf("%s was accepted", name)
		}
	}
}

// The property that matters most: these parse bytes an attacker chose, on a
// host whose job is to keep watching. A malformed frame must cost one dropped
// packet and nothing else.
func TestTruncationNeverPanics(t *testing.T) {
	full := buildARP(ARPReply, router, "10.0.4.1", attacker, "10.0.4.48")
	for i := 0; i <= len(full); i++ {
		eth, ok := ParseEthernet(full[:i])
		if !ok {
			continue
		}
		if _, ok := ParseARP(eth.Payload); ok && i < len(full) {
			t.Errorf("a %d-byte prefix of a %d-byte frame parsed as a complete ARP message",
				i, len(full))
		}
	}
}

// A frame that is nothing but VLAN tags must terminate rather than spin.
func TestStackedVLANTagsTerminate(t *testing.T) {
	var b bytes.Buffer
	b.Write(make([]byte, 12))
	for i := 0; i < 64; i++ {
		binary.Write(&b, binary.BigEndian, uint16(EtherTypeVLAN)) //nolint:errcheck
		binary.Write(&b, binary.BigEndian, uint16(1))             //nolint:errcheck
	}
	eth, ok := ParseEthernet(b.Bytes())
	if ok && (eth.EtherType == EtherTypeVLAN || eth.EtherType == EtherTypeQinQ) {
		t.Error("parser returned a frame still claiming to be a vlan tag")
	}
}

func TestMACFormatting(t *testing.T) {
	if got := router.String(); got != "00:11:32:c3:cb:d6" {
		t.Errorf("String() = %q, want the canonical form osq also produces", got)
	}
	if got := router.OUI(); got != "00:11:32" {
		t.Errorf("OUI() = %q", got)
	}
	if !bcast.IsBroadcast() || (MAC{}).IsBroadcast() {
		t.Error("broadcast detection wrong")
	}
	if !(MAC{}).IsZero() || router.IsZero() {
		t.Error("zero detection wrong")
	}
	// 0x7a has bit 1 set: locally administered.
	if !(MAC{0x7a, 0x0d, 0x75, 0x19, 0x48, 0x84}).IsLocallyAdministered() {
		t.Error("locally administered bit missed")
	}
	if router.IsLocallyAdministered() {
		t.Error("real hardware reported as locally administered")
	}
}

// FuzzParse is the real assurance for a hostile-input parser: no input of any
// shape may panic.
func FuzzParse(f *testing.F) {
	f.Add(buildARP(ARPReply, router, "10.0.4.1", attacker, "10.0.4.48"))
	f.Add(buildARP(ARPRequest, attacker, "0.0.0.0", MAC{}, "10.0.4.77"))
	f.Add([]byte{})
	f.Add(make([]byte, 14))
	f.Fuzz(func(t *testing.T, b []byte) {
		eth, ok := ParseEthernet(b)
		if !ok {
			return
		}
		if a, ok := ParseARP(eth.Payload); ok {
			_ = a.IsGratuitous()
			_ = a.IsProbe()
			_ = a.SenderMAC.String()
		}
	})
}

// The DHCP, name-resolution and IP parsers all read attacker-controlled bytes.
// No input of any shape may panic.
func FuzzParseUDPLayers(f *testing.F) {
	f.Add(make([]byte, 60))
	f.Add(make([]byte, 300))
	f.Fuzz(func(t *testing.T, b []byte) {
		if d, ok := ParseUDPDatagram(b); ok {
			ParseDHCP(d.UDP.Payload)
			ParseNameAnswers(MDNSPort, d.UDP.Payload)
			ParseNameAnswers(LLMNRPort, d.UDP.Payload)
			ParseNameAnswers(NBNSPort, d.UDP.Payload)
		}
		// Directly, too: the datagram gate is not the only caller.
		ParseNameAnswers(NBNSPort, b)
		ParseDHCP(b)
		if ip, ok := ParseIPv4(b); ok {
			ParseUDP(ip.Payload)
		}
		if ip, ok := ParseIPv6(b); ok {
			ParseUDP(ip.Payload)
		}
	})
}

// encodeNBNSName is the inverse of the first-level encoding, for testing the
// decoder against known names with each service-type suffix.
func encodeNBNSName(name string, service byte) []byte {
	padded := make([]byte, 16)
	for i := range padded {
		padded[i] = ' '
	}
	copy(padded[:15], name) // at most 15 name chars; the 16th is the service byte
	padded[15] = service
	out := make([]byte, 32)
	for i, b := range padded {
		out[2*i] = 'A' + (b >> 4)
		out[2*i+1] = 'A' + (b & 0x0f)
	}
	return out
}

// The bug this guards: the service-type byte is 0x00 (Workstation) or 0x20
// (Server) for the two commonest record types, both in the padding cutset, so
// trimming padding before removing it positionally ate a real character.
func TestNBNSNameDecodeAcrossServiceTypes(t *testing.T) {
	for _, name := range []string{"FILESERVER", "WPAD", "A", "DESKTOP-ABC1234"} {
		var got0, got20 string
		for _, svc := range []byte{0x00, 0x03, 0x1b, 0x1d, 0x1e, 0x20} {
			enc := encodeNBNSName(name, svc)
			got := decodeNBNSName(enc)
			if got != name {
				t.Errorf("service 0x%02x: decoded %q, want %q", svc, got, name)
			}
			if svc == 0x00 {
				got0 = got
			}
			if svc == 0x20 {
				got20 = got
			}
		}
		// The two that used to be wrong must now match the others.
		if got0 != name || got20 != name {
			t.Errorf("%q: workstation=%q server=%q, want both %q", name, got0, got20, name)
		}
	}
}
