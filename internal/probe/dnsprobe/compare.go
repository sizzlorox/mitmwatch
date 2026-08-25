package dnsprobe

import (
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/sizzlorox/mitmwatch/internal/probe"
)

const (
	vecDisagrees      = "dns/resolver-disagrees"
	vecNXDomainToA    = "dns/nxdomain-to-a"
	vecDoHUnreachable = "dns/doh-unreachable"
)

// Prefix granularity for comparison. Exact-IP matching is wrong for anything
// behind a CDN or anycast: the local resolver and a DoH endpoint routinely
// return different edges of the same service. Agreeing on the announced
// network is the durable signal; exact matching is reserved for owned domains
// once phase 2 adds ASN lookups at the witness.
const (
	v4Bits = 24
	v6Bits = 48
)

func (Probe) Compare(_, cur probe.Snapshot, cc probe.CompareCtx) []probe.Finding {
	var now snapshot
	if ok, err := cur.Decode(&now); !ok || err != nil {
		return nil
	}

	var out []probe.Finding
	add := func(f probe.Finding) {
		f.Probe = name
		if f.Score == 0 {
			f.Score = cc.Weight(f.Vector)
		}
		out = append(out, f)
	}

	// One finding for the whole comparison channel, not one per endpoint. An
	// unreachable channel is worth saying out loud - it is the expected symptom
	// when something is intercepting TLS, because the DoH client refuses to
	// trust anything outside the embedded bundle - but saying it twice does not
	// make it twice as true.
	if down := sortedKeys(now.DoHErr); len(down) > 0 {
		ev := map[string]string{
			"endpoints": strings.Join(down, ", "),
			"note":      "verified against the built-in certificate list only, never this computer's",
		}
		for _, ep := range down {
			ev["error: "+ep] = now.DoHErr[ep]
		}
		add(probe.Finding{
			Vector: vecDoHUnreachable, Target: "network",
			Title:    "Could not reach an independent name-lookup service to compare against",
			Evidence: ev,
		})
	}

	for _, host := range sortedKeys(now.System) {
		sys := now.System[host]

		// Corroborate across endpoints before reporting, and emit at most one
		// finding per vector per host.
		//
		// Emitting per endpoint made the score track DoH uptime rather than the
		// evidence: two endpoints made every DNS finding worth double its entry
		// in the weight table, which pushed the coarsest and most CDN-prone
		// check through the learning window that is meant to hold it, while one
		// endpoint being down quietly halved the same hijack back to Medium.
		// Adding a third endpoint for robustness would have made it worth
		// triple. clockprobe already had this right: corroborate, then report
		// once at table weight, with the per-source detail in the evidence.
		var reachable, nx, disagree []string
		for _, ep := range sortedKeys(now.DoH) {
			ref, ok := now.DoH[ep][host]
			if !ok || ref.Err != "" {
				continue // the endpoint itself is already reported above
			}
			reachable = append(reachable, ep)
			switch {
			case ref.NXDomain && len(sys.IPs) > 0:
				nx = append(nx, ep)
			case len(ref.IPs) > 0 && len(sys.IPs) > 0 && !prefixOverlap(sys.IPs, ref.IPs):
				disagree = append(disagree, ep+" -> "+strings.Join(ref.IPs, " "))
			}
		}
		if len(reachable) == 0 {
			continue
		}

		// Unanimity is the bar. If one endpoint disagrees and another agrees
		// with the local resolver, the endpoints disagree with each other -
		// which says nothing about whether this network is lying.
		switch {
		case len(nx) == len(reachable):
			add(probe.Finding{
				Vector: vecNXDomainToA, Target: host,
				Title: "Your network invented an address for a name that does not exist",
				// Not the addresses, which change per query. Accepting this
				// means "this host may be answered locally", which is what
				// split-horizon DNS legitimately looks like.
				Evidence: map[string]string{
					"host": host, "local_answer": strings.Join(sys.IPs, ", "),
					"independent_answer": "does not exist",
					"checked_against":    strings.Join(reachable, ", "),
				},
			})
		case len(nx)+len(disagree) == len(reachable):
			add(probe.Finding{
				Vector: vecDisagrees, Target: host,
				Title: "Your network sends " + host + " somewhere different from everyone else",
				Evidence: map[string]string{
					"host": host, "local_answer": strings.Join(sys.IPs, ", "),
					"independent_answers": strings.Join(disagree, "; "),
					"checked_against":     strings.Join(reachable, ", "),
					"compared_at":         "/24 and /48 prefixes",
				},
			})
		}
	}
	return out
}

// prefixOverlap reports whether any address in a shares a network prefix with
// any address in b.
func prefixOverlap(a, b []string) bool {
	set := map[netip.Prefix]bool{}
	for _, s := range a {
		if p, ok := maskOf(s); ok {
			set[p] = true
		}
	}
	if len(set) == 0 {
		// Nothing comparable on one side: do not manufacture a disagreement.
		return true
	}
	any := false
	for _, s := range b {
		p, ok := maskOf(s)
		if !ok {
			continue
		}
		any = true
		if set[p] {
			return true
		}
	}
	return !any
}

func maskOf(s string) (netip.Prefix, bool) {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		if parsed := net.ParseIP(s); parsed != nil {
			if ip, err = netip.ParseAddr(parsed.String()); err != nil {
				return netip.Prefix{}, false
			}
		} else {
			return netip.Prefix{}, false
		}
	}
	ip = ip.Unmap()
	bits := v4Bits
	if ip.Is6() {
		bits = v6Bits
	}
	p, err := ip.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
