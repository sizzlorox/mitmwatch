package dhcpprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/frame"
	"github.com/sizzlorox/mitmwatch/internal/osq"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

// offer builds a real Ethernet/IPv4/UDP/DHCP OFFER, so these tests exercise the
// same parse path as the wire rather than a hand-filled snapshot.
type offerOpts struct {
	srcMAC   string
	srcIP    string
	serverID string
	routers  []string
	dns      []string
	wpad     string
	msgType  uint8
}

func buildOffer(o offerOpts) frame.Frame {
	if o.msgType == 0 {
		o.msgType = frame.DHCPOffer
	}
	var dhcp bytes.Buffer
	dhcp.WriteByte(2)                                         // op: BOOTREPLY
	dhcp.WriteByte(1)                                         // htype ethernet
	dhcp.WriteByte(6)                                         // hlen
	dhcp.WriteByte(0)                                         // hops
	binary.Write(&dhcp, binary.BigEndian, uint32(0xdeadbeef)) //nolint:errcheck // xid
	dhcp.Write(make([]byte, 4))                               // secs + flags
	dhcp.Write(make([]byte, 4))                               // ciaddr
	yi := netip.MustParseAddr("10.0.4.77").As4()
	dhcp.Write(yi[:])                // yiaddr
	dhcp.Write(make([]byte, 8))      // siaddr + giaddr
	dhcp.Write(make([]byte, 16))     // chaddr
	dhcp.Write(make([]byte, 64+128)) // sname + file
	dhcp.Write([]byte{0x63, 0x82, 0x53, 0x63})

	opt := func(code byte, val []byte) {
		dhcp.WriteByte(code)
		dhcp.WriteByte(byte(len(val)))
		dhcp.Write(val)
	}
	opt(53, []byte{o.msgType})
	if o.serverID != "" {
		a := netip.MustParseAddr(o.serverID).As4()
		opt(54, a[:])
	}
	packAddrs := func(code byte, ips []string) {
		if len(ips) == 0 {
			return
		}
		var b []byte
		for _, s := range ips {
			a := netip.MustParseAddr(s).As4()
			b = append(b, a[:]...)
		}
		opt(code, b)
	}
	packAddrs(3, o.routers)
	packAddrs(6, o.dns)
	if o.wpad != "" {
		opt(252, []byte(o.wpad))
	}
	dhcp.WriteByte(255)

	payload := dhcp.Bytes()

	var udp bytes.Buffer
	binary.Write(&udp, binary.BigEndian, uint16(frame.DHCPServerPort)) //nolint:errcheck
	binary.Write(&udp, binary.BigEndian, uint16(frame.DHCPClientPort)) //nolint:errcheck
	binary.Write(&udp, binary.BigEndian, uint16(8+len(payload)))       //nolint:errcheck
	binary.Write(&udp, binary.BigEndian, uint16(0))                    //nolint:errcheck // checksum
	udp.Write(payload)
	udpBytes := udp.Bytes()

	var ip bytes.Buffer
	ip.WriteByte(0x45)
	ip.WriteByte(0)
	binary.Write(&ip, binary.BigEndian, uint16(20+len(udpBytes))) //nolint:errcheck
	ip.Write(make([]byte, 4))
	ip.WriteByte(64)             // ttl
	ip.WriteByte(frame.ProtoUDP) // protocol
	ip.Write(make([]byte, 2))    // checksum
	src := netip.MustParseAddr(o.srcIP).As4()
	ip.Write(src[:])
	dst := netip.MustParseAddr("255.255.255.255").As4()
	ip.Write(dst[:])
	ip.Write(udpBytes)
	ipBytes := ip.Bytes()

	var eth bytes.Buffer
	eth.Write([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	for _, part := range strings.Split(o.srcMAC, ":") {
		var v int
		for _, c := range part {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= int(c - '0')
			case c >= 'a' && c <= 'f':
				v |= int(c-'a') + 10
			}
		}
		eth.WriteByte(byte(v))
	}
	binary.Write(&eth, binary.BigEndian, uint16(frame.EtherTypeIPv4)) //nolint:errcheck
	eth.Write(ipBytes)

	return frame.Frame{Time: time.Now(), Iface: "test", Data: eth.Bytes()}
}

const (
	realRouter = "00:11:32:c3:cb:d6"
	rogue      = "dc:a6:32:11:22:33"
)

func inputs(t *testing.T, base probe.Snapshot, frames ...frame.Frame) probe.Inputs {
	t.Helper()
	ch := make(chan frame.Frame, len(frames)+1)
	for _, f := range frames {
		ch <- f
	}
	close(ch)
	return probe.Inputs{
		Frames:        ch,
		CaptureWindow: 2 * time.Second,
		Baseline:      base,
		Config:        config.Defaults(),
		Network: osq.NetworkIdentity{
			GatewayIP: "10.0.4.1", Resolvers: []string{"10.0.4.1"},
		},
	}
}

func cc() probe.CompareCtx {
	return probe.CompareCtx{
		Config: config.Defaults(), Trust: "home",
		Network: osq.NetworkIdentity{GatewayIP: "10.0.4.1", Resolvers: []string{"10.0.4.1"}},
	}
}

func observe(t *testing.T, in probe.Inputs) probe.Snapshot {
	t.Helper()
	s, err := (Probe{}).Observe(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func vectors(fs []probe.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.Vector] = f.Score
	}
	return out
}

func legitimate() frame.Frame {
	return buildOffer(offerOpts{
		srcMAC: realRouter, srcIP: "10.0.4.1", serverID: "10.0.4.1",
		routers: []string{"10.0.4.1"}, dns: []string{"10.0.4.1"},
	})
}

func TestLegitimateOfferIsSilent(t *testing.T) {
	first := observe(t, inputs(t, probe.Snapshot{}, legitimate()))
	// Second pass with the same server already in the baseline.
	second := observe(t, inputs(t, first, legitimate()))
	if fs := (Probe{}).Compare(first, second, cc()); len(fs) != 0 {
		t.Fatalf("the network's own router produced %v", vectors(fs))
	}
}

// The attack: an offer naming a gateway that is not this network's gateway.
func TestRogueGatewayIsHigh(t *testing.T) {
	f := buildOffer(offerOpts{
		srcMAC: rogue, srcIP: "10.0.4.66", serverID: "10.0.4.66",
		routers: []string{"10.0.4.66"}, dns: []string{"10.0.4.66"},
	})
	base := observe(t, inputs(t, probe.Snapshot{}, legitimate()))
	cur := observe(t, inputs(t, base, f))

	got := vectors((Probe{}).Compare(base, cur, cc()))
	if got[vecRogueGateway] < 60 {
		t.Fatalf("%s scored %d, want >= 60: %v", vecRogueGateway, got[vecRogueGateway], got)
	}
	if _, ok := got[vecUnexpectedServer]; !ok {
		t.Errorf("a server never seen before was not reported: %v", got)
	}
}

// Option 252 hands out a proxy URL. Almost nothing on a home network has a
// legitimate reason to.
func TestWPADOfferIsReported(t *testing.T) {
	f := buildOffer(offerOpts{
		srcMAC: rogue, srcIP: "10.0.4.1", serverID: "10.0.4.1",
		routers: []string{"10.0.4.1"}, dns: []string{"10.0.4.1"},
		wpad: "http://10.0.4.66/wpad.dat",
	})
	base := observe(t, inputs(t, probe.Snapshot{}, legitimate()))
	cur := observe(t, inputs(t, base, f))

	fs := (Probe{}).Compare(base, cur, cc())
	got := vectors(fs)
	if got[vecWPADOffered] < 40 {
		t.Fatalf("%s scored %d: %v", vecWPADOffered, got[vecWPADOffered], got)
	}
	for _, x := range fs {
		if x.Vector == vecWPADOffered && !strings.Contains(x.Evidence["proxy_url"], "wpad.dat") {
			t.Errorf("evidence lost the url: %v", x.Evidence)
		}
	}
}

func TestRogueDNSIsReported(t *testing.T) {
	f := buildOffer(offerOpts{
		srcMAC: realRouter, srcIP: "10.0.4.1", serverID: "10.0.4.1",
		routers: []string{"10.0.4.1"}, dns: []string{"10.0.4.66"},
	})
	base := observe(t, inputs(t, probe.Snapshot{}, legitimate()))
	cur := observe(t, inputs(t, base, f))
	if got := vectors((Probe{}).Compare(base, cur, cc())); got[vecRogueDNS] == 0 {
		t.Fatalf("want %s, got %v", vecRogueDNS, got)
	}
}

// The accumulation property. DHCP is rare, so almost every window is empty, and
// an empty window must not erase what earlier windows learned - otherwise every
// server looks new again the next time it speaks.
func TestEmptyWindowKeepsWhatWasLearned(t *testing.T) {
	first := observe(t, inputs(t, probe.Snapshot{}, legitimate()))
	var s1 snapshot
	if _, err := first.Decode(&s1); err != nil {
		t.Fatal(err)
	}
	if len(s1.Servers) != 1 {
		t.Fatalf("first pass recorded %d servers, want 1", len(s1.Servers))
	}

	quiet := observe(t, inputs(t, first)) // no frames at all
	var s2 snapshot
	if _, err := quiet.Decode(&s2); err != nil {
		t.Fatal(err)
	}
	if len(s2.Servers) != 1 {
		t.Fatalf("a quiet window erased the accumulated servers: %v", s2.Servers)
	}
	if len(s2.SeenThisPass) != 0 {
		t.Errorf("a quiet window claimed to have seen %v", s2.SeenThisPass)
	}
	// And nothing is reported for a server that did not speak.
	if fs := (Probe{}).Compare(first, quiet, cc()); len(fs) != 0 {
		t.Fatalf("a quiet window produced %v", vectors(fs))
	}
}

// A client's own DISCOVER/REQUEST offers nothing and must not be recorded as a
// server, or every device on the network becomes a DHCP server.
func TestClientMessagesAreIgnored(t *testing.T) {
	f := buildOffer(offerOpts{
		srcMAC: rogue, srcIP: "0.0.0.0", serverID: "",
		msgType: frame.DHCPDiscover,
	})
	cur := observe(t, inputs(t, probe.Snapshot{}, f))
	var s snapshot
	if _, err := cur.Decode(&s); err != nil {
		t.Fatal(err)
	}
	if len(s.Servers) != 0 {
		t.Fatalf("a client DISCOVER was recorded as a server: %v", s.Servers)
	}
}

func TestTwoServersInOneWindowIsCorroboration(t *testing.T) {
	base := observe(t, inputs(t, probe.Snapshot{}, legitimate()))
	cur := observe(t, inputs(t, base,
		legitimate(),
		buildOffer(offerOpts{srcMAC: rogue, srcIP: "10.0.4.66", serverID: "10.0.4.66",
			routers: []string{"10.0.4.66"}}),
	))
	got := vectors((Probe{}).Compare(base, cur, cc()))
	if _, ok := got[vecMultipleServers]; !ok {
		t.Fatalf("want %s, got %v", vecMultipleServers, got)
	}
	// It must be corroboration, not the loudest signal: the offered settings
	// are what actually identify the attack.
	if got[vecMultipleServers] >= got[vecRogueGateway] {
		t.Errorf("multiple-servers (%d) outranks rogue-gateway (%d); a clipped sample "+
			"would then be louder than real evidence", got[vecMultipleServers], got[vecRogueGateway])
	}
}

// First sight has no baseline. Learn, do not accuse.
func TestFirstSightDoesNotAccuse(t *testing.T) {
	cur := observe(t, inputs(t, probe.Snapshot{}, legitimate()))
	if got := vectors((Probe{}).Compare(probe.Snapshot{}, cur, cc())); len(got) != 0 {
		t.Fatalf("first sight produced %v", got)
	}
}

func TestMalformedFramesDoNotStopTheWindow(t *testing.T) {
	junk := frame.Frame{Data: []byte{0x01, 0x02, 0x03}}
	short := frame.Frame{Data: make([]byte, 20)}
	cur := observe(t, inputs(t, probe.Snapshot{}, junk, short, legitimate()))
	var s snapshot
	if _, err := cur.Decode(&s); err != nil {
		t.Fatal(err)
	}
	if len(s.Servers) != 1 {
		t.Fatalf("the valid offer was lost among malformed frames: %v", s.Servers)
	}
	if s.Frames != 3 {
		t.Errorf("frame count = %d, want all 3 counted", s.Frames)
	}
}

// Regression: the server set accumulates, the settings must not.
//
// Merging offers across passes diluted them - a rogue offer of 10.0.4.66 union
// last hour's legitimate 10.0.4.1 read as a server offering both, and every
// settings rule found something acceptable in the union and stayed silent. The
// probe was quietly useless against the exact attack it exists for.
func TestOffersAreJudgedPerPassNotAccumulated(t *testing.T) {
	base := observe(t, inputs(t, probe.Snapshot{}, legitimate()))

	// Same server, now offering a different gateway.
	turned := buildOffer(offerOpts{
		srcMAC: realRouter, srcIP: "10.0.4.1", serverID: "10.0.4.1",
		routers: []string{"10.0.4.66"}, dns: []string{"10.0.4.66"},
	})
	cur := observe(t, inputs(t, base, turned))

	var s snapshot
	if _, err := cur.Decode(&s); err != nil {
		t.Fatal(err)
	}
	if got := s.Offers["10.0.4.1"].Routers; len(got) != 1 || got[0] != "10.0.4.66" {
		t.Fatalf("this pass's offer = %v, want only what was offered now", got)
	}
	if _, ok := s.Servers["10.0.4.1"]; !ok {
		t.Error("the server set stopped accumulating")
	}

	got := vectors((Probe{}).Compare(base, cur, cc()))
	if got[vecRogueGateway] == 0 {
		t.Fatalf("a server that turned rogue was masked by its own history: %v", got)
	}
}

// Regression for the freeze deadlock. In the field the FIRST real DHCP sighting
// never lands in pass one: the window is 5s every 2min, so almost every early
// pass is empty, and an empty pass still produces a non-empty snapshot. Gating
// on hasBase made that first empty pass flip the guard, so the first real
// sighting always accused the honest router - and because it was a High Change,
// the freeze rule then refused to adopt the snapshot that would have learned
// the server, forever.
func TestFirstRealSightingAfterEmptyPassesIsSilent(t *testing.T) {
	// Several empty passes first, threading the baseline as the runner would.
	base := probe.Snapshot{}
	for i := 0; i < 3; i++ {
		s := observe(t, inputs(t, base)) // no frames
		base = s
	}
	// Now the honest router's lease renews inside a window for the first time.
	cur := observe(t, inputs(t, base, legitimate()))
	if got := vectors((Probe{}).Compare(base, cur, cc())); len(got) != 0 {
		t.Fatalf("the honest router was accused on its first sighting after quiet passes: %v", got)
	}
}

// And once a server is known, a genuinely new one is still caught.
func TestNewServerAfterKnownOneIsReported(t *testing.T) {
	base := probe.Snapshot{}
	for i := 0; i < 2; i++ {
		base = observe(t, inputs(t, base))
	}
	// Learn the real router.
	known := observe(t, inputs(t, base, legitimate()))
	// The runner would adopt it, since no High Change fires now.
	rogue := buildOffer(offerOpts{srcMAC: rogue, srcIP: "10.0.4.66", serverID: "10.0.4.66",
		routers: []string{"10.0.4.66"}})
	cur := observe(t, inputs(t, known, legitimate(), rogue))
	got := vectors((Probe{}).Compare(known, cur, cc()))
	if _, ok := got[vecUnexpectedServer]; !ok {
		t.Fatalf("a genuinely new server was not reported: %v", got)
	}
}

// A host resolving through a loopback stub (systemd-resolved, Pi-hole, dnsmasq)
// says nothing about the network's resolvers, so the comparison must be skipped
// rather than always firing.
func TestLoopbackStubResolverDoesNotFalseFireRogueDNS(t *testing.T) {
	c := cc()
	c.Network.Resolvers = []string{"127.0.0.53"} // systemd-resolved
	base := observe(t, inputs(t, probe.Snapshot{}, legitimate()))
	// Router offers a real public resolver, which does not intersect 127.0.0.53.
	f := buildOffer(offerOpts{srcMAC: realRouter, srcIP: "10.0.4.1", serverID: "10.0.4.1",
		routers: []string{"10.0.4.1"}, dns: []string{"1.1.1.1"}})
	cur := observe(t, inputs(t, base, f))
	if got := vectors((Probe{}).Compare(base, cur, c)); got[vecRogueDNS] != 0 {
		t.Fatalf("a loopback stub resolver produced a false rogue-dns: %v", got)
	}
}

// But a real resolver list still catches a rogue DNS offer.
func TestRealResolverStillCatchesRogueDNS(t *testing.T) {
	c := cc()
	c.Network.Resolvers = []string{"10.0.4.1"}
	base := observe(t, inputs(t, probe.Snapshot{}, legitimate()))
	f := buildOffer(offerOpts{srcMAC: realRouter, srcIP: "10.0.4.1", serverID: "10.0.4.1",
		routers: []string{"10.0.4.1"}, dns: []string{"10.0.4.66"}})
	cur := observe(t, inputs(t, base, f))
	if got := vectors((Probe{}).Compare(base, cur, c)); got[vecRogueDNS] == 0 {
		t.Fatal("a rogue DNS offer was missed with a real resolver list")
	}
}
