// Package capture selects the best available frame source for the host and
// reports which tier is in effect.
package capture

import (
	"github.com/sizzlorox/mitmwatch/internal/frame"
)

// Tier is the capture backend in use. Lower is more capable.
type Tier int

const (
	Tier1Pcap    Tier = 1 // libpcap/Npcap via gopacket, build tag `pcap`
	Tier2Raw     Tier = 2 // AF_PACKET (linux) / /dev/bpf (darwin), pure Go
	Tier3Polling Tier = 3 // OS tables + active probes, no privileges
)

func (t Tier) String() string {
	switch t {
	case Tier1Pcap:
		return "1 (pcap)"
	case Tier2Raw:
		return "2 (raw sockets)"
	case Tier3Polling:
		return "3 (polling)"
	}
	return "unknown"
}

// Coverage is the one-line plain-language consequence of running at this tier.
func (t Tier) Coverage() string {
	switch t {
	case Tier1Pcap:
		return "full passive capture, including mirror-port traffic"
	case Tier2Raw:
		return "passive capture of everything this interface can see, including traffic between other devices"
	case Tier3Polling:
		return "only what this host has resolved for itself; traffic between other devices is invisible"
	}
	return ""
}

// Stats is what the backend has handled since it opened.
//
// It exists because a closed or silent channel is otherwise indistinguishable
// between "the link is quiet", "the interface went down", "the filter is wrong
// and drops everything" and "the ring overflowed". A detector that cannot tell
// those apart reports a quiet network in all four cases, and three of them are
// wrong. Dropped is what says the sensor is losing frames it should have seen.
type Stats struct {
	Received uint64
	Dropped  uint64
}

// Source feeds link-layer frames to the event-driven probes. A probe never
// knows which tier is behind it.
type Source interface {
	Tier() Tier
	// Reason explains why this tier and not a better one. Empty at tier 1.
	Reason() string
	// Iface is the interface being watched, empty when the tier does not
	// attach to one.
	Iface() string
	Frames() <-chan frame.Frame
	// Err reports why the source stopped, or nil while it is healthy. A caller
	// that sees the channel close must consult this before concluding anything
	// from the silence.
	Err() error
	Stats() Stats
	Close() error
}

// Open selects the best capture backend available on this host.
//
// ifaces may be empty, in which case the platform picks the interface carrying
// the default route. Falling back to tier 3 is normal and not an error: an
// unprivileged laptop is a supported deployment, and `doctor` states plainly
// what that costs.
func Open(ifaces []string) (Source, error) {
	return open(ifaces)
}

// pollSource is the tier 3 fallback: no frames, only what the OS tables say.
// The arp probe reads those tables directly rather than through this channel.
type pollSource struct {
	ch     chan frame.Frame
	reason string
}

func newPollSource(reason string) *pollSource {
	ch := make(chan frame.Frame)
	close(ch) // never yields a frame; closed so a range over it terminates
	return &pollSource{ch: ch, reason: reason}
}

func (p *pollSource) Tier() Tier                 { return Tier3Polling }
func (p *pollSource) Reason() string             { return p.reason }
func (p *pollSource) Iface() string              { return "" }
func (p *pollSource) Frames() <-chan frame.Frame { return p.ch }
func (p *pollSource) Err() error                 { return nil }
func (p *pollSource) Stats() Stats               { return Stats{} }
func (p *pollSource) Close() error               { return nil }
