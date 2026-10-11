package web

import (
	"fmt"
	"strings"
	"time"
)

// PathHop is one step of a route, ready to draw.
type PathHop struct {
	TTL   int
	Addr  string // empty when nothing answered
	Class string // gateway | local | internet | unknown
	Delay time.Duration
}

// PathView is one route to one target as seen from one vantage.
//
// The diagram is drawn here from the hop list alone: no map tiles, no address
// geolocation. Either would send the household's routing to a third party,
// which is the one thing this tool must never do.
type PathView struct {
	Vantage string // Inside (sensor) or Outside (witness)
	Target  string
	Hops    []PathHop
	Reached bool
}

const (
	hopStep   = 110
	hopMargin = 60
)

// Width is the SVG width: source, every hop, then the destination.
func (p PathView) Width() int { return p.Last() + hopMargin }

// Node is one circle in the diagram.
type Node struct {
	X     int
	Label string
	Sub   string
	Class string
}

// Nodes lays the route out left to right: this host, each hop, the target.
func (p PathView) Nodes() []Node {
	nodes := []Node{{X: hopMargin, Label: "This host", Class: "self"}}
	hops := p.Hops
	// The traced target answers as the final hop; drawing it again as the
	// destination would show one device twice.
	atTarget := p.Reached && len(hops) > 0 && hops[len(hops)-1].Addr != ""
	if atTarget {
		hops = hops[:len(hops)-1]
	}
	for i, h := range hops {
		label, sub := h.Addr, h.Class
		if h.Addr == "" {
			label, sub = "?", "no answer"
		} else if h.Delay > 0 {
			sub += " · " + formatDelay(h.Delay)
		}
		nodes = append(nodes, Node{X: hopMargin + hopStep*(i+1), Label: label, Sub: sub, Class: h.Class})
	}
	end := Node{X: hopMargin + hopStep*(len(hops)+1), Label: p.Target, Sub: "destination", Class: "dest"}
	if atTarget && p.Hops[len(p.Hops)-1].Delay > 0 {
		end.Sub += " · " + formatDelay(p.Hops[len(p.Hops)-1].Delay)
	}
	if !p.Reached {
		end.Sub = "not reached"
		end.Class = "unknown"
	}
	return append(nodes, end)
}

// Last is the x of the final node, for the connecting line.
func (p PathView) Last() int { return p.Nodes()[len(p.Nodes())-1].X }

// Summary is the one-line text alternative to the diagram.
func (p PathView) Summary() string {
	status := "not reached"
	if p.Reached {
		status = "reached"
	}
	hops := make([]string, len(p.Hops))
	for i, h := range p.Hops {
		addr := h.Addr
		if addr == "" {
			addr = "no reply"
		}
		hops[i] = fmt.Sprintf("hop %d: %s (%s%s)", h.TTL, h.Class, addr, summaryDelay(h.Delay))
	}
	if len(hops) == 0 {
		return fmt.Sprintf("Route to %s: %s; no hops observed", p.Target, status)
	}
	return fmt.Sprintf("Route to %s: %s; %s", p.Target, status, strings.Join(hops, "; "))
}

func formatDelay(d time.Duration) string {
	return d.Round(time.Microsecond).String()
}

func summaryDelay(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return "; " + formatDelay(d)
}
