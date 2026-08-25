package ndprobe

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

// raOpts describes a Router Advertisement to synthesize onto the wire, so the
// tests exercise ParseRouterAdvert - the real parse path - not a hand-filled
// snapshot.
type raOpts struct {
	srcMAC   string
	srcIP    string // link-local source
	lifetime uint16
	prefix   string // e.g. "2001:db8::/64"
	dns      string // RDNSS address, optional
	hopLimit uint8  // 0 -> defaults to 255 (a valid on-link RA)
}

func buildRA(o raOpts) frame.Frame {
	if o.hopLimit == 0 {
		o.hopLimit = 255
	}
	var ic bytes.Buffer
	ic.WriteByte(frame.ICMPv6RouterAdvert)          // type 134
	ic.WriteByte(0)                                 // code
	ic.Write([]byte{0, 0})                          // checksum (unchecked here)
	ic.WriteByte(64)                                // cur hop limit
	ic.WriteByte(0)                                 // flags
	binary.Write(&ic, binary.BigEndian, o.lifetime) //nolint:errcheck // router lifetime
	ic.Write(make([]byte, 8))                       // reachable + retrans

	if o.prefix != "" {
		p := netip.MustParsePrefix(o.prefix)
		ic.WriteByte(3) // prefix info option
		ic.WriteByte(4) // length: 4*8 = 32 bytes
		ic.WriteByte(byte(p.Bits()))
		ic.WriteByte(0)            // flags
		ic.Write(make([]byte, 12)) // valid + preferred + reserved
		a := p.Addr().As16()
		ic.Write(a[:]) // 16-byte prefix
	}
	if o.dns != "" {
		ic.WriteByte(25)          // RDNSS
		ic.WriteByte(3)           // length: 3*8 = 24 bytes
		ic.Write([]byte{0, 0})    // reserved
		ic.Write(make([]byte, 4)) // lifetime
		a := netip.MustParseAddr(o.dns).As16()
		ic.Write(a[:])
	}
	icBytes := ic.Bytes()

	var ip bytes.Buffer
	ip.WriteByte(0x60)                                        // version 6
	ip.Write([]byte{0, 0, 0})                                 // tc + flow
	binary.Write(&ip, binary.BigEndian, uint16(len(icBytes))) //nolint:errcheck // payload len
	ip.WriteByte(frame.ProtoICMPv6)                           // next header 58
	ip.WriteByte(o.hopLimit)
	src := netip.MustParseAddr(o.srcIP).As16()
	ip.Write(src[:])
	dst := netip.MustParseAddr("ff02::1").As16() // all-nodes
	ip.Write(dst[:])
	ip.Write(icBytes)
	ipBytes := ip.Bytes()

	var eth bytes.Buffer
	eth.Write([]byte{0x33, 0x33, 0, 0, 0, 1}) // IPv6 all-nodes multicast dst
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
	binary.Write(&eth, binary.BigEndian, uint16(frame.EtherTypeIPv6)) //nolint:errcheck
	eth.Write(ipBytes)

	return frame.Frame{Time: time.Now(), Iface: "test", Data: eth.Bytes()}
}

const (
	realRouter = "00:11:32:c3:cb:d6"
	rogue      = "dc:a6:32:11:22:33"
	realLL     = "fe80::211:32ff:fec3:cbd6"
	rogueLL    = "fe80::dea6:32ff:fe11:2233"
)

func inputs(base probe.Snapshot, frames ...frame.Frame) probe.Inputs {
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
		Network:       osq.NetworkIdentity{Resolvers: []string{"10.0.4.1"}},
	}
}

func cc() probe.CompareCtx {
	return probe.CompareCtx{
		Config: config.Defaults(), Trust: "home",
		Network: osq.NetworkIdentity{Resolvers: []string{"10.0.4.1"}},
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
	return buildRA(raOpts{srcMAC: realRouter, srcIP: realLL, lifetime: 1800, prefix: "2001:db8:1::/64"})
}

// The network's own router, seen twice, must be silent.
func TestLegitimateRAIsSilent(t *testing.T) {
	first := observe(t, inputs(probe.Snapshot{}, legitimate()))
	second := observe(t, inputs(first, legitimate()))
	if fs := (Probe{}).Compare(first, second, cc()); len(fs) != 0 {
		t.Fatalf("the network's own router produced %v", vectors(fs))
	}
}

// A second device advertising itself as a router is the SLAAC attack.
func TestNewRouterIsHigh(t *testing.T) {
	base := observe(t, inputs(probe.Snapshot{}, legitimate()))
	cur := observe(t, inputs(base, legitimate(), buildRA(raOpts{
		srcMAC: rogue, srcIP: rogueLL, lifetime: 1800, prefix: "2001:db8:1::/64",
	})))
	got := vectors((Probe{}).Compare(base, cur, cc()))
	if got[vecNewRouter] < 60 {
		t.Fatalf("%s scored %d, want >= 60: %v", vecNewRouter, got[vecNewRouter], got)
	}
}

// An honest router advertising RDNSS from the very first sighting must be
// silent. RDNSS is always an IPv6 address and the host's resolver list is
// typically IPv4 (10.0.4.1) or 127.0.0.53 - comparing across families would
// false-fire on every SLAAC router. The RDNSS is baselined, not accused.
func TestHonestRDNSSIsSilent(t *testing.T) {
	ra := func() frame.Frame {
		return buildRA(raOpts{srcMAC: realRouter, srcIP: realLL, lifetime: 1800, dns: "2606:4700:4700::1111"})
	}
	first := observe(t, inputs(probe.Snapshot{}, ra()))
	second := observe(t, inputs(first, ra()))
	if fs := (Probe{}).Compare(first, second, cc()); len(fs) != 0 {
		t.Fatalf("a router honestly advertising RDNSS produced %v", vectors(fs))
	}
}

// The real attack: the EXISTING router's advertised resolver changes to a new
// one. Change-detected against that router's own baseline, never the host list.
func TestExistingRouterDNSChangeFires(t *testing.T) {
	base := observe(t, inputs(probe.Snapshot{}, buildRA(raOpts{
		srcMAC: realRouter, srcIP: realLL, lifetime: 1800, dns: "2606:4700:4700::1111",
	})))
	cur := observe(t, inputs(base, buildRA(raOpts{
		srcMAC: realRouter, srcIP: realLL, lifetime: 1800, dns: "2001:4860:4860::8888",
	})))
	got := vectors((Probe{}).Compare(base, cur, cc()))
	if _, ok := got[vecRogueDNS]; !ok {
		t.Fatalf("an existing router changing its advertised resolver was not reported: %v", got)
	}
}

// The protocol's own anti-spoof rule: an RA with hop limit < 255 was forwarded
// and is not a legitimate on-link RA. It must not even parse.
func TestForwardedRARejected(t *testing.T) {
	_, ok := frame.ParseRouterAdvert(buildRA(raOpts{
		srcMAC: rogue, srcIP: rogueLL, lifetime: 1800, hopLimit: 200,
	}).Data)
	if ok {
		t.Fatal("an RA with hop limit 200 parsed as a valid on-link RA")
	}
}

// A zero-lifetime RA is a router deprecating itself, not claiming to route.
// A new MAC sending one must not raise new-router.
func TestZeroLifetimeNotARouter(t *testing.T) {
	base := observe(t, inputs(probe.Snapshot{}, legitimate()))
	cur := observe(t, inputs(base, buildRA(raOpts{
		srcMAC: rogue, srcIP: rogueLL, lifetime: 0, prefix: "2001:db8:1::/64",
	})))
	if got := vectors((Probe{}).Compare(base, cur, cc())); got[vecNewRouter] != 0 {
		t.Fatalf("a zero-lifetime RA was scored as a router: %v", got)
	}
}

// An IPv4-only network - no RAs at all - must be silent, and must not adopt a
// captured-but-empty snapshot in a way that later reads as a change.
func TestIPv4OnlyIsSilent(t *testing.T) {
	base := observe(t, inputs(probe.Snapshot{})) // no frames
	cur := observe(t, inputs(base))
	if fs := (Probe{}).Compare(base, cur, cc()); len(fs) != 0 {
		t.Fatalf("a network with no IPv6 produced %v", vectors(fs))
	}
}

// The first real sighting after empty baselines must not accuse: a network that
// only now captured its first RA has no prior router to contradict.
func TestFirstSightingDoesNotAccuse(t *testing.T) {
	base := observe(t, inputs(probe.Snapshot{})) // captured, no routers
	cur := observe(t, inputs(base, legitimate()))
	if fs := (Probe{}).Compare(base, cur, cc()); len(fs) != 0 {
		t.Fatalf("the first router ever seen was reported: %v", vectors(fs))
	}
}
