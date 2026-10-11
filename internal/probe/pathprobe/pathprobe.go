// Package pathprobe records the route packets take towards a few fixed targets.
//
// A man in the middle on the local segment is, to a router's eyes, one more
// hop: traffic that used to leave through the gateway now passes through a
// second device first. Tracing the path and comparing it with the one learned
// earlier is a direct view of that, independent of the ARP and DHCP tables an
// attacker can also forge.
//
// It observes only. It sends TTL-limited ICMP echoes - the same thing
// traceroute does - to the configured targets and reads what comes back.
package pathprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/sizzlorox/mitmwatch/internal/probe"
)

const name = "path"

// Hop is one step of a path. Addr is empty when nothing answered at that TTL,
// which routers do routinely (ICMP rate limiting), so it is shown as unknown
// and never read as either a change or a confirmation.
type Hop struct {
	TTL  int    `json:"ttl"`
	Addr string `json:"addr,omitempty"`
}

// Path is the route to one target.
type Path struct {
	Target  string `json:"target"`
	Hops    []Hop  `json:"hops"`
	Reached bool   `json:"reached"`
}

type snapshot struct {
	Paths []Path `json:"paths"`
}

// Decode returns the paths held in a snapshot, for display.
func Decode(s probe.Snapshot) []Path {
	var snap snapshot
	if ok, err := s.Decode(&snap); !ok || err != nil {
		return nil
	}
	return snap.Paths
}

type Probe struct{}

func init() { probe.Register(Probe{}) }

func (Probe) Name() string            { return name }
func (Probe) Interval() time.Duration { return 10 * time.Minute }

func (Probe) Observe(ctx context.Context, in probe.Inputs) (probe.Snapshot, error) {
	cfg := in.Config.Trace
	targets := cfg.Targets
	if len(targets) == 0 {
		return probe.Incomplete(name, snapshot{}, errors.New("no path targets configured"))
	}

	// A raw ICMP socket needs privilege. Not having it is a failure to look,
	// reported as one - an empty path list would read as a clean network.
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return probe.Incomplete(name, snapshot{}, fmt.Errorf("raw ICMP socket unavailable (needs root/administrator): %w", err))
	}
	defer conn.Close()
	pc := conn.IPv4PacketConn()

	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = time.Second
	}
	maxHops := cfg.MaxHops
	if maxHops <= 0 || maxHops > 30 {
		maxHops = 12
	}

	var snap snapshot
	var failures []string
	for i, target := range targets {
		p, err := trace(ctx, conn, pc, target, uint16(os.Getpid()&0xffff), uint16(i+1)<<8, maxHops, timeout)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", target, err))
		}
		snap.Paths = append(snap.Paths, p)
	}
	if len(failures) > 0 {
		return probe.Incomplete(name, snap, errors.New(strings.Join(failures, "; ")))
	}
	return probe.Encode(name, snap)
}

func trace(ctx context.Context, conn *icmp.PacketConn, pc *ipv4.PacketConn, target string,
	id, seqBase uint16, maxHops int, timeout time.Duration) (Path, error) {
	p := Path{Target: target}
	dst, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return p, err
	}

	answered := 0
	for ttl := 1; ttl <= maxHops; ttl++ {
		if err := ctx.Err(); err != nil {
			return p, err
		}
		seq := seqBase + uint16(ttl)
		hop := Hop{TTL: ttl}
		addr, reached, err := probeTTL(conn, pc, dst, ttl, id, seq, timeout)
		if err != nil {
			return p, err
		}
		if addr != "" {
			hop.Addr = addr
			answered++
		}
		p.Hops = append(p.Hops, hop)
		if reached {
			p.Reached = true
			break
		}
	}
	// Not one router answered: the probe was filtered or mis-sent, not "the
	// path is empty".
	if answered == 0 {
		return p, errors.New("no hop answered")
	}
	return p, nil
}

func probeTTL(conn *icmp.PacketConn, pc *ipv4.PacketConn, dst *net.IPAddr, ttl int,
	id, seq uint16, timeout time.Duration) (addr string, reached bool, err error) {
	if err := pc.SetTTL(ttl); err != nil {
		return "", false, err
	}
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: int(id), Seq: int(seq), Data: []byte("mitmwatch")}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return "", false, err
	}
	if _, err := conn.WriteTo(b, dst); err != nil {
		return "", false, err
	}
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 1500)
	for {
		conn.SetReadDeadline(deadline) //nolint:errcheck // a failure surfaces as a read error below
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return "", false, nil
			}
			return "", false, err
		}
		from, ok := matchReply(buf[:n], id, seq)
		if !ok {
			continue // someone else's traffic on the shared raw socket
		}
		if ip, ok := peer.(*net.IPAddr); ok {
			from.addr = ip.IP.String()
		} else {
			return "", false, fmt.Errorf("reply from unexpected peer type %T", peer)
		}
		return from.addr, from.final, nil
	}
}

type reply struct {
	addr  string
	final bool
}

// matchReply decides whether an ICMP message answers our probe (id, seq). A
// time-exceeded quotes the start of the original datagram, which is where the
// id and sequence are recovered; an echo reply carries them directly.
func matchReply(b []byte, id, seq uint16) (reply, bool) {
	m, err := icmp.ParseMessage(1, b)
	if err != nil {
		return reply{}, false
	}
	switch body := m.Body.(type) {
	case *icmp.Echo:
		if m.Type == ipv4.ICMPTypeEchoReply && body.ID == int(id) && body.Seq == int(seq) {
			return reply{final: true}, true
		}
	case *icmp.TimeExceeded:
		return matchQuoted(body.Data, id, seq, false)
	case *icmp.DstUnreach:
		// The target (or a router) refused: the path ends here.
		return matchQuoted(body.Data, id, seq, true)
	}
	return reply{}, false
}

func matchQuoted(data []byte, id, seq uint16, final bool) (reply, bool) {
	if len(data) < 20 || data[0]>>4 != 4 {
		return reply{}, false
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl+8 {
		return reply{}, false
	}
	inner := data[ihl:]
	if inner[0] != 8 { // our echo request
		return reply{}, false
	}
	if binary.BigEndian.Uint16(inner[4:6]) != id || binary.BigEndian.Uint16(inner[6:8]) != seq {
		return reply{}, false
	}
	return reply{final: final}, true
}

// local reports whether an address is on the household side of the path:
// private, link-local or loopback space. Hops are classed this way because the
// route inside a home is stable and short, while beyond it routing legitimately
// varies from probe to probe.
func local(addr string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	return a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLoopback()
}

// Class names a hop's role for display.
func Class(addr string, ttl int) string {
	switch {
	case addr == "":
		return "unknown"
	case ttl == 1:
		return "gateway"
	case local(addr):
		return "local"
	default:
		return "internet"
	}
}
