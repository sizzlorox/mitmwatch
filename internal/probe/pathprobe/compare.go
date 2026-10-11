package pathprobe

import (
	"strconv"
	"strings"

	"github.com/sizzlorox/mitmwatch/internal/probe"
)

const (
	vecFirstHop    = "path/first-hop-changed"
	vecHopInserted = "path/hop-inserted"
	vecUnavailable = "path/unavailable"
)

// Compare looks for a device that has put itself between this host and the
// internet.
//
// Only the household side of the path is compared. Beyond the first public
// hop, a different router from one probe to the next is ordinary load
// balancing and ISP routing; scoring it would make the tool cry wolf daily. An
// interceptor on the local network, by contrast, shows up as a new first hop or
// as an extra private-address hop before the path leaves the building.
//
// An unanswered hop is unknown, not different: it is skipped rather than
// matched against anything.
func (Probe) Compare(base, cur probe.Snapshot, cc probe.CompareCtx) []probe.Finding {
	var out []probe.Finding
	add := func(f probe.Finding) {
		f.Probe = name
		f.Score = cc.Weight(f.Vector)
		out = append(out, f)
	}
	unavailable := func(why string) {
		add(probe.Finding{
			Vector: vecUnavailable, Target: "network",
			Title:    "Could not trace the route out of this network, so a device placed in the path would go unnoticed",
			Evidence: map[string]string{"error": why},
		})
	}

	// Checked before decoding: an observation that failed, or cannot be read,
	// must say so rather than fall through to "nothing to report".
	var now snapshot
	ok, err := cur.Decode(&now)
	if err != nil {
		unavailable(err.Error())
		return out
	}
	if cur.Degraded {
		unavailable(cur.Err)
	}
	if !ok {
		return out
	}

	var before snapshot
	if ok, err := base.Decode(&before); !ok || err != nil {
		return out // no baseline yet: nothing to compare against
	}
	old := map[string]Path{}
	for _, p := range before.Paths {
		old[p.Target] = p
	}

	for _, p := range now.Paths {
		b, ok := old[p.Target]
		if !ok {
			continue
		}
		bl, cl := localPrefix(b), localPrefix(p)

		if bf, cf := firstAddr(b), firstAddr(p); bf != "" && cf != "" && bf != cf {
			add(probe.Finding{
				Vector: vecFirstHop, Target: p.Target, Change: true,
				Title:    "Traffic to " + p.Target + " now leaves through a different first router than before",
				Identity: map[string]string{"first": cf},
				Evidence: map[string]string{"was": bf, "now": cf, "path": render(p)},
			})
			continue
		}

		known := map[string]bool{}
		unknown := map[int]bool{}
		for _, h := range bl {
			if h.Addr == "" {
				unknown[h.TTL] = true
			} else {
				known[h.Addr] = true
			}
		}
		var added []string
		for _, h := range cl {
			if h.Addr != "" && !known[h.Addr] && !unknown[h.TTL] {
				added = append(added, h.Addr)
			}
		}
		if len(added) > 0 {
			add(probe.Finding{
				Vector: vecHopInserted, Target: p.Target, Change: true,
				Title:    "A new device appears in the route to " + p.Target + " inside your network",
				Identity: map[string]string{"added": strings.Join(added, ",")},
				Evidence: map[string]string{"new": strings.Join(added, ", "), "was": render(b), "now": render(p)},
			})
		}
	}
	return out
}

func firstAddr(p Path) string {
	if len(p.Hops) == 0 {
		return ""
	}
	return p.Hops[0].Addr
}

// localPrefix is the run of household-side hops from the start of the path,
// unanswered ones kept as "" placeholders so positions stay honest.
func localPrefix(p Path) []Hop {
	var out []Hop
	for _, h := range p.Hops {
		if h.Addr != "" && !local(h.Addr) {
			break
		}
		out = append(out, h)
	}
	return out
}

func render(p Path) string {
	parts := make([]string, len(p.Hops))
	for i, h := range p.Hops {
		if h.Addr == "" {
			parts[i] = "*"
		} else {
			parts[i] = h.Addr
		}
	}
	return strconv.Itoa(len(p.Hops)) + " hops: " + strings.Join(parts, " > ")
}
