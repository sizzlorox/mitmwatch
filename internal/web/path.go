package web

import "fmt"

// PathHop is one step of a route, ready to draw.
type PathHop struct {
	TTL   int
	Addr  string // empty when nothing answered
	Class string // gateway | local | internet | unknown
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
func (p PathView) Width() int { return hopMargin*2 + hopStep*(len(p.Hops)+1) }

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
	for i, h := range p.Hops {
		label, sub := h.Addr, h.Class
		if h.Addr == "" {
			label, sub = "?", "no answer"
		}
		nodes = append(nodes, Node{X: hopMargin + hopStep*(i+1), Label: label, Sub: sub, Class: h.Class})
	}
	end := Node{X: hopMargin + hopStep*(len(p.Hops)+1), Label: p.Target, Sub: "destination", Class: "dest"}
	if !p.Reached {
		end.Sub = "not reached"
		end.Class = "unknown"
	}
	return append(nodes, end)
}

// Last is the x of the final node, for the connecting line.
func (p PathView) Last() int { return hopMargin + hopStep*(len(p.Hops)+1) }

// Summary is the one-line text alternative to the diagram.
func (p PathView) Summary() string {
	return fmt.Sprintf("%d hop(s) to %s", len(p.Hops), p.Target)
}
