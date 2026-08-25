// Package dhcpprobe watches who is handing out network settings.
//
// A rogue DHCP server is a man-in-the-middle that needs no packet forgery at
// all. It answers a client's ordinary request with its own address as the
// gateway, or its own resolver as DNS, and the client configures itself to send
// everything through the attacker - voluntarily, and permanently, until the
// lease expires. On most networks it does not even have to win a race: many
// clients take the first answer.
//
// What is scored is what was *offered*, not how many servers answered.
// Correlating OFFERs to DISCOVERs needs both halves of an exchange inside one
// capture window, and a short window routinely catches an OFFER whose DISCOVER
// it never saw - so counting offers would report a false conflict whenever the
// sampling clipped a conversation. The settings inside an offer, compared
// against what this network actually uses, need no correlation and no luck.
//
// The observation is cumulative. DHCP is rare traffic - a lease renews every
// few hours - so almost every window sees nothing at all, and an empty window
// must not erase what earlier windows learned. Each pass merges into the
// baseline rather than replacing it.
package dhcpprobe

import (
	"context"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/frame"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

const name = "dhcp"

// serverObs is everything one DHCP server has been seen offering.
type serverObs struct {
	// MAC is the hardware address the offers came from, which is the part a
	// rogue server cannot borrow from the real one without also winning ARP.
	MAC       string    `json:"mac,omitempty"`
	Routers   []string  `json:"routers,omitempty"`
	DNS       []string  `json:"dns,omitempty"`
	WPAD      string    `json:"wpad,omitempty"`
	Messages  []string  `json:"messages,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type snapshot struct {
	// Servers is keyed by the server's address, accumulated across passes.
	Servers map[string]serverObs `json:"servers,omitempty"`
	// Captured says listening happened, so an empty Servers map can be told
	// apart from never having looked.
	Captured bool `json:"captured"`
	Frames   int  `json:"frames,omitempty"`
	// SeenThisPass is which servers spoke during this window, so Compare can
	// tell a live observation from an accumulated memory.
	SeenThisPass []string `json:"seen_this_pass,omitempty"`
	// Offers is what each server offered THIS pass, unmerged.
	//
	// The split matters. Servers accumulates so that a quiet window does not
	// erase what earlier windows learned, but accumulating the *settings* would
	// dilute them: a rogue offer of 10.0.4.66 merged with last hour's legitimate
	// 10.0.4.1 reads as a server that offers both, and every settings rule then
	// finds something acceptable in the union and stays silent. Judge the offer
	// in front of you; remember only that the server exists.
	Offers map[string]serverObs `json:"offers,omitempty"`
}

type Probe struct{}

func init() { probe.Register(Probe{}) }

func (Probe) Name() string            { return name }
func (Probe) ConsumesFrames() bool    { return true }
func (Probe) Interval() time.Duration { return 2 * time.Minute }

func (Probe) Observe(ctx context.Context, in probe.Inputs) (probe.Snapshot, error) {
	// Start from what is already known. DHCP is rare enough that most windows
	// are empty, and replacing the accumulated view with an empty one would
	// make every server look new again the next time it spoke.
	snap := snapshot{Servers: map[string]serverObs{}, Offers: map[string]serverObs{}}
	var prev snapshot
	if ok, _ := in.Baseline.Decode(&prev); ok {
		for k, v := range prev.Servers {
			snap.Servers[k] = v
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
			d, ok := frame.ParseUDPDatagram(f.Data)
			if !ok {
				continue
			}
			// Both directions of the conversation live on 67/68; only the
			// server's half carries settings, and MsgType tells them apart.
			if d.UDP.SrcPort != frame.DHCPServerPort && d.UDP.DstPort != frame.DHCPServerPort {
				continue
			}
			msg, ok := frame.ParseDHCP(d.UDP.Payload)
			if !ok {
				continue
			}
			if msg.MsgType != frame.DHCPOffer && msg.MsgType != frame.DHCPAck {
				continue // DISCOVER and REQUEST come from clients and offer nothing
			}

			// Prefer the server identifier the server states over the source
			// address it happens to have used: option 54 is what the client
			// will believe and address later.
			id := msg.ServerID
			if !id.IsValid() || id.IsUnspecified() {
				id = d.IP.Src
			}
			key := id.String()
			seen[key] = true

			now := time.Now().UTC()

			// Accumulated: this server exists, and when it was first and last
			// heard from.
			acc := snap.Servers[key]
			if acc.FirstSeen.IsZero() {
				acc.FirstSeen = now
			}
			acc.LastSeen = now
			acc.MAC = d.Eth.Src.String()
			snap.Servers[key] = acc

			// This pass only: what it actually offered, judged on its own.
			cur := snap.Offers[key]
			cur.MAC = d.Eth.Src.String()
			cur.FirstSeen, cur.LastSeen = now, now
			cur.Routers = mergeAddrs(cur.Routers, msg.Routers)
			cur.DNS = mergeAddrs(cur.DNS, msg.DNS)
			if msg.WPAD != "" {
				cur.WPAD = msg.WPAD
			}
			cur.Messages = mergeStrings(cur.Messages, frame.MsgTypeName(msg.MsgType))
			snap.Offers[key] = cur
		}
	}

	snap.SeenThisPass = sortedSet(seen)
	return probe.Encode(name, snap)
}

func mergeAddrs(have []string, add []netip.Addr) []string {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	for _, a := range add {
		if a.IsValid() && !a.IsUnspecified() {
			set[a.String()] = true
		}
	}
	return sortedSet(set)
}

func mergeStrings(have []string, add ...string) []string {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	for _, a := range add {
		set[a] = true
	}
	return sortedSet(set)
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

const (
	vecRogueGateway     = "dhcp/rogue-gateway"
	vecWPADOffered      = "dhcp/wpad-offered"
	vecUnexpectedServer = "dhcp/unexpected-server"
	vecRogueDNS         = "dhcp/rogue-dns"
	vecMultipleServers  = "dhcp/multiple-servers"
)

func (Probe) Compare(base, cur probe.Snapshot, cc probe.CompareCtx) []probe.Finding {
	var now snapshot
	if ok, err := cur.Decode(&now); !ok || err != nil {
		return nil
	}
	var prev snapshot
	base.Decode(&prev) //nolint:errcheck // absence handled by len(prev.Servers)

	var out []probe.Finding
	add := func(f probe.Finding) {
		f.Probe = name
		if f.Score == 0 {
			f.Score = cc.Weight(f.Vector)
		}
		out = append(out, f)
	}

	// Only servers that actually spoke this pass are judged. The rest are
	// memory, already reported when they were new.
	gateway := cc.Network.GatewayIP
	knownResolvers := map[string]bool{}
	for _, r := range cc.Network.Resolvers {
		knownResolvers[r] = true
	}

	for _, ip := range now.SeenThisPass {
		// The offer in front of us, never the accumulated union - see the note
		// on snapshot.Offers.
		o := now.Offers[ip]

		// A server this network has not seen before is worth saying out loud
		// even if what it offered looks reasonable - it is the shape of the
		// attack, and the settings are the confirmation.
		//
		// The gate is "have we ever recorded a server here", not "do we have a
		// baseline at all". hasBase is true after the first pass ever, because
		// even a window that saw no DHCP still encodes a non-empty snapshot -
		// so gating on hasBase made the FIRST real sighting the accusing one,
		// on every honest network. And because this is a High Change, the
		// runner's freeze rule then refused to adopt the snapshot that would
		// have learned the server, so the network's own router was re-announced
		// forever. len(prev.Servers) is the honest predicate: it is zero until
		// a server has actually been recorded and adopted.
		if len(prev.Servers) > 0 {
			if _, existed := prev.Servers[ip]; !existed {
				add(probe.Finding{
					Vector: vecUnexpectedServer, Target: ip,
					Title:    "A new device started handing out network settings",
					Change:   true,
					Identity: map[string]string{"server": ip},
					Evidence: map[string]string{
						"server":      ip,
						"hardware":    o.MAC,
						"offered":     describeOffer(o),
						"benign_case": "a replaced router, or a second router someone plugged in, looks like this too",
						"what_to_do":  "if you did not add a router or access point, unplug what you do not recognise",
					},
				})
			}
		}

		// The settings themselves. These need no correlation and no luck: an
		// offer naming a gateway that is not this network's gateway is trying
		// to move traffic, whoever sent it.
		if gateway != "" && len(o.Routers) > 0 && !contains(o.Routers, gateway) {
			add(probe.Finding{
				Vector: vecRogueGateway, Target: ip,
				Identity: map[string]string{"server": ip, "routers": strings.Join(o.Routers, ",")},
				Title:    "Something is telling devices to send their traffic somewhere else",
				Evidence: map[string]string{
					"server":         ip,
					"hardware":       o.MAC,
					"offered_router": strings.Join(o.Routers, ", "),
					"real_gateway":   gateway,
					"what_to_do":     "treat this network as untrusted until you find what is offering this",
				},
			})
		}

		// Skip the DNS comparison when this host resolves through a loopback
		// stub - systemd-resolved (127.0.0.53), a local Pi-hole, dnsmasq,
		// unbound, Docker's resolver. In that case /etc/resolv.conf names only
		// the stub, so it says nothing about what the network hands out, and the
		// intersection with any real offered resolver is empty by construction.
		// Comparing anyway made rogue-dns a constant, not a comparison - and it
		// stacked with unexpected-server on the same target to reach Critical on
		// an untouched network.
		if len(knownResolvers) > 0 && !allLoopback(cc.Network.Resolvers) &&
			len(o.DNS) > 0 && !anyIn(o.DNS, knownResolvers) {
			add(probe.Finding{
				Vector: vecRogueDNS, Target: ip,
				Identity: map[string]string{"server": ip, "dns": strings.Join(o.DNS, ",")},
				Title:    "Something is telling devices to look up websites somewhere else",
				Evidence: map[string]string{
					"server":         ip,
					"offered_dns":    strings.Join(o.DNS, ", "),
					"this_host_uses": strings.Join(cc.Network.Resolvers, ", "),
					"benign_case":    "a guest network or a second subnet can legitimately use different resolvers",
				},
			})
		}

		// Option 252 hands out a proxy configuration URL. Almost nothing on a
		// home network has a legitimate reason to, and a client that honours it
		// sends everything through whatever the URL names.
		if o.WPAD != "" {
			add(probe.Finding{
				Vector: vecWPADOffered, Target: ip,
				Identity: map[string]string{"server": ip, "wpad": o.WPAD},
				Title:    "Something is telling devices to route traffic through a proxy",
				Evidence: map[string]string{
					"server":     ip,
					"proxy_url":  o.WPAD,
					"option":     "252 (WPAD)",
					"what_to_do": "unless your workplace configured this, treat the network as untrusted",
				},
			})
		}
	}

	// Corroboration, not the primary signal: two servers answering in one
	// window is suspicious, but a short sample can clip a conversation and a
	// network can legitimately have a second server on another subnet.
	if len(now.SeenThisPass) > 1 {
		add(probe.Finding{
			Vector: vecMultipleServers, Target: "network",
			Identity: map[string]string{"servers": strings.Join(now.SeenThisPass, ",")},
			Title:    "More than one device is handing out network settings",
			Evidence: map[string]string{
				"servers":     strings.Join(now.SeenThisPass, ", "),
				"count":       strconv.Itoa(len(now.SeenThisPass)),
				"benign_case": "a mesh system or a second router in bridge mode can do this legitimately",
			},
		})
	}
	return out
}

func describeOffer(o serverObs) string {
	var parts []string
	if len(o.Routers) > 0 {
		parts = append(parts, "gateway "+strings.Join(o.Routers, "/"))
	}
	if len(o.DNS) > 0 {
		parts = append(parts, "dns "+strings.Join(o.DNS, "/"))
	}
	if o.WPAD != "" {
		parts = append(parts, "proxy config "+o.WPAD)
	}
	if len(parts) == 0 {
		return "no settings decoded"
	}
	return strings.Join(parts, ", ")
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// allLoopback reports whether every resolver is a loopback address, meaning the
// host's resolver list is a local stub and reveals nothing about the network's.
func allLoopback(resolvers []string) bool {
	if len(resolvers) == 0 {
		return false
	}
	for _, r := range resolvers {
		ip, err := netip.ParseAddr(r)
		if err != nil || !ip.IsLoopback() {
			return false
		}
	}
	return true
}

func anyIn(vals []string, set map[string]bool) bool {
	for _, v := range vals {
		if set[v] {
			return true
		}
	}
	return false
}
