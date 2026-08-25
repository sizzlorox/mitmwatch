// Package ndprobe watches IPv6 Router Advertisements for a rogue router.
//
// On a dual-stack network, hosts prefer IPv6, so whoever sends Router
// Advertisements decides the default gateway and the DNS resolvers for
// everything - and unlike ARP, this needs no reply to a request, just an
// unsolicited announcement. An attacker who sends RAs becomes the man in the
// middle for all traffic, and because IPv6 is often unmonitored on home
// networks, it is a quieter attack than ARP spoofing.
//
// The detection is the same shape as the arp gateway watch, and safe the same
// way: a new router advertising itself where a different router did before is
// the signal, and everything is baselined per network so an honest network with
// one router is silent. On an IPv4-only network there are no RAs at all, so the
// probe is simply quiet - correctly, not by luck.
package ndprobe

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/frame"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

const name = "nd"

// routerObs is one router seen advertising during the window.
type routerObs struct {
	MAC       string   `json:"mac"`
	LinkLocal string   `json:"link_local"`
	Lifetime  int      `json:"lifetime"`
	Prefixes  []string `json:"prefixes,omitempty"`
	DNS       []string `json:"dns,omitempty"`
}

type snapshot struct {
	// Routers is keyed by the advertising router's MAC, accumulated across
	// passes because RAs are periodic and a single window may miss one.
	Routers map[string]routerObs `json:"routers,omitempty"`
	// SeenThisPass is which routers actually advertised in this window.
	SeenThisPass []string `json:"seen_this_pass,omitempty"`
	Captured     bool     `json:"captured"`
	Frames       int      `json:"frames,omitempty"`
}

type Probe struct{}

func init() { probe.Register(Probe{}) }

func (Probe) Name() string            { return name }
func (Probe) ConsumesFrames() bool    { return true }
func (Probe) Interval() time.Duration { return 2 * time.Minute }

func (Probe) Observe(ctx context.Context, in probe.Inputs) (probe.Snapshot, error) {
	// Accumulate: an RA every few seconds means most windows see the router,
	// but a quiet window must not erase it.
	snap := snapshot{Routers: map[string]routerObs{}}
	var prev snapshot
	if ok, _ := in.Baseline.Decode(&prev); ok {
		for k, v := range prev.Routers {
			snap.Routers[k] = v
		}
	}

	if in.Frames == nil || in.CaptureWindow <= 0 {
		return probe.Encode(name, snap)
	}
	snap.Captured = true

	seen := map[string]bool{}
	deadline := time.NewTimer(in.CaptureWindow)
	defer deadline.Stop()

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-deadline.C:
			break loop
		case f, ok := <-in.Frames:
			if !ok {
				break loop
			}
			snap.Frames++
			ra, ok := frame.ParseRouterAdvert(f.Data)
			if !ok {
				continue
			}
			// Only a default-router claim matters. An RA with zero lifetime is
			// a router deprecating itself, not asserting routing authority.
			if !ra.IsDefaultRouter() {
				continue
			}
			key := ra.RouterMAC.String()
			seen[key] = true
			snap.Routers[key] = routerObs{
				MAC:       key,
				LinkLocal: ra.RouterIP.String(),
				Lifetime:  int(ra.Lifetime),
				Prefixes:  prefixStrings(ra.Prefixes),
				DNS:       addrStrings(ra.DNS),
			}
		}
	}
	snap.SeenThisPass = sortedKeys(seen)
	return probe.Encode(name, snap)
}

const (
	vecNewRouter = "nd/new-router"
	vecRogueDNS  = "nd/rogue-dns"
)

func (Probe) Compare(base, cur probe.Snapshot, cc probe.CompareCtx) []probe.Finding {
	var now snapshot
	if ok, err := cur.Decode(&now); !ok || err != nil {
		return nil
	}
	if !now.Captured {
		return nil
	}
	var prev snapshot
	base.Decode(&prev) //nolint:errcheck // absence handled by len(prev.Routers)

	var out []probe.Finding
	add := func(f probe.Finding) {
		f.Probe = name
		if f.Score == 0 {
			f.Score = cc.Weight(f.Vector)
		}
		out = append(out, f)
	}

	for _, mac := range now.SeenThisPass {
		r := now.Routers[mac]

		// A router advertising where a different one did before. The gate is
		// "we have recorded a router here", not "we have a baseline at all", so
		// the first real sighting after quiet windows does not accuse - the
		// same fix the dhcp probe needed.
		if len(prev.Routers) > 0 {
			if _, existed := prev.Routers[mac]; !existed {
				add(probe.Finding{
					Vector: vecNewRouter, Target: r.LinkLocal,
					Change:   true,
					Identity: map[string]string{"router_mac": mac},
					Title:    "A new device is claiming to be your IPv6 router",
					Evidence: map[string]string{
						"router_mac":  mac + vendorHint(mac),
						"link_local":  r.LinkLocal,
						"prefixes":    strings.Join(r.Prefixes, ", "),
						"why":         "on a network with IPv6, traffic prefers it; a device that convinces others it is the IPv6 router sees everything",
						"benign_case": "a replaced router, or a second router someone plugged in, looks like this too",
						"what_to_do":  "if you did not add a router, disconnect what you do not recognise and treat the network as untrusted",
					},
				})
			}
		}

		// An existing router whose advertised resolvers changed: a spoofer that
		// took over the real router's identity and pointed DNS at itself. This
		// is change-detection against this router's own baselined RDNSS - never
		// a comparison against the host's resolver list, which is a different
		// address family (an RDNSS value is always IPv6, the host's resolvers
		// are typically IPv4 or 127.0.0.53) and would false-fire on every honest
		// router doing SLAAC. The first RDNSS a router advertises is baselined
		// silently; only a newly appearing resolver on an already-known router
		// speaks. A brand-new router is nd/new-router's job, above.
		if p, existed := prev.Routers[mac]; existed && len(r.DNS) > 0 {
			had := map[string]bool{}
			for _, d := range p.DNS {
				had[d] = true
			}
			var added []string
			for _, d := range r.DNS {
				if !had[d] {
					added = append(added, d)
				}
			}
			if len(added) > 0 {
				add(probe.Finding{
					Vector: vecRogueDNS, Target: r.LinkLocal,
					Change:   true,
					Identity: map[string]string{"router_mac": mac, "added_dns": strings.Join(added, ",")},
					Title:    "Your IPv6 router changed which server devices use to look up websites",
					Evidence: map[string]string{
						"router_mac":  mac,
						"new_dns":     strings.Join(added, ", "),
						"was_dns":     strings.Join(p.DNS, ", "),
						"why":         "whoever controls the DNS server your devices are told to use can redirect any website",
						"benign_case": "a router firmware update that changes the built-in resolver looks like this too",
					},
				})
			}
		}
	}
	return out
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	sort.Strings(out)
	return out
}

func addrStrings(as []netip.Addr) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.String())
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// vendorHint reuses the same short OUI cues the arp probe uses; a locally
// administered address is a strong tell for a software-generated router.
func vendorHint(mac string) string {
	if len(mac) < 2 {
		return ""
	}
	if b := hexByte(mac[:2]); b >= 0 && b&0x02 != 0 {
		return " (randomised or software-assigned address)"
	}
	return ""
}

func hexByte(s string) int {
	v := 0
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= int(c - '0')
		case c >= 'a' && c <= 'f':
			v |= int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= int(c-'A') + 10
		default:
			return -1
		}
	}
	return v
}
