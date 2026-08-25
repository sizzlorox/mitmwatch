// Package arpprobe watches who claims to be the gateway.
//
// This is the classic home-network man-in-the-middle. An attacker on the same
// segment answers ARP for the router's address, every other device updates its
// table, and all their traffic goes through the attacker's machine first. It
// needs no password, no vulnerability and no privileged position - only being
// on the same Wi-Fi.
//
// The probe deliberately works at capture tier 3, from the host's own neighbour
// table, so it runs today on any platform without raw sockets or elevated
// privileges. That is weaker than watching the wire: the table only shows
// bindings this host has resolved, so an attacker poisoning a *different*
// victim and leaving the sensor alone is invisible here. Phase 1's passive
// capture sees those; this sees the case where the sensor itself is a target,
// which is also the case where the sensor's own findings would be lies.
//
// How much of the table exists varies enormously, and that shapes what the
// second rule can see. A workstation that talks to everything on the LAN
// resolves dozens of neighbours; a headless sensor that talks to almost nothing
// resolves two. Measured on the same segment: 40 entries on a desktop, 2 on a
// Raspberry Pi. The gateway rule is unaffected - the gateway is always resolved,
// because everything routes through it - but the shared-address rule can only
// notice a spoofer whose own address this host happens to have resolved. That
// is another reason phase 1's passive capture matters: broadcast ARP is visible
// whether or not this host ever spoke to the sender.
//
// It is only trustworthy because the profile key no longer includes the gateway
// MAC. While it did, spoofing the gateway selected a fresh profile with an
// empty baseline, so this comparison had nothing to compare against precisely
// when it mattered.
package arpprobe

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/frame"
	"github.com/sizzlorox/mitmwatch/internal/osq"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

const name = "arp"

type snapshot struct {
	GatewayIP  string `json:"gateway_ip"`
	GatewayMAC string `json:"gateway_mac,omitempty"`
	// Neighbors maps address to MAC, for the whole resolved table.
	Neighbors map[string]string `json:"neighbors,omitempty"`

	// Claims is what the wire showed: address -> MAC -> how many times that
	// MAC claimed that address during the capture window. Empty at tier 3.
	//
	// This is what the neighbour table cannot give. The table holds one winner
	// per address; the wire holds the argument. Two MACs claiming one address
	// is the argument in progress.
	Claims map[string]map[string]int `json:"claims,omitempty"`
	// Captured records that listening actually happened, so an empty Claims
	// map can be told apart from never having looked.
	Captured bool   `json:"captured"`
	Frames   int    `json:"frames,omitempty"`
	Err      string `json:"err,omitempty"`
}

// Probe is the arp detector.
type Probe struct{}

func init() { probe.Register(Probe{}) }

func (Probe) Name() string { return name }

// ConsumesFrames marks this probe as capture-fed, so the runner subscribes it
// to the frame stream. At tier 3 the subscription yields nothing and the probe
// falls back to the neighbour table.
func (Probe) ConsumesFrames() bool { return true }

// Interval is short. A poisoning that lasts two minutes is long enough to
// collect credentials, and reading a neighbour table costs nothing.
func (Probe) Interval() time.Duration { return 2 * time.Minute }

func (Probe) Observe(ctx context.Context, in probe.Inputs) (probe.Snapshot, error) {
	snap := snapshot{
		GatewayIP:  in.Network.GatewayIP,
		GatewayMAC: in.Network.GatewayMAC,
		Neighbors:  map[string]string{},
	}

	ns, err := osq.Neighbors(ctx)
	if err != nil {
		// An unreadable neighbour table is not an empty one. Saying so keeps
		// the baseline from recording "this network has no devices".
		snap.Err = err.Error()
		return probe.Incomplete(name, snap, err)
	}
	for _, n := range ns {
		snap.Neighbors[n.IP] = n.MAC
	}

	if in.Frames != nil && in.CaptureWindow > 0 {
		snap.Claims, snap.Frames = listen(ctx, in.Frames, in.CaptureWindow)
		snap.Captured = true
	}
	// The identity query and the table are two reads of the same kernel state.
	// Prefer the table when they disagree about the gateway, since it is the
	// one this probe compares against.
	if mac, ok := snap.Neighbors[snap.GatewayIP]; ok && mac != "" {
		snap.GatewayMAC = mac
	}
	return probe.Encode(name, snap)
}

// listen drains the capture channel for the window and records who claimed
// what.
//
// Only claims count. An ARP request asking "who has 10.0.4.1" says nothing
// about the asker's ownership of it, and an RFC 5227 probe with an all-zero
// sender is asking whether an address is free - counting either as a claim
// would report every host that joins the network.
func listen(ctx context.Context, frames <-chan frame.Frame, window time.Duration) (map[string]map[string]int, int) {
	claims := map[string]map[string]int{}
	deadline := time.NewTimer(window)
	defer deadline.Stop()

	n := 0
	for {
		select {
		case <-ctx.Done():
			return claims, n
		case <-deadline.C:
			return claims, n
		case f, ok := <-frames:
			if !ok {
				return claims, n
			}
			n++
			eth, ok := frame.ParseEthernet(f.Data)
			if !ok || eth.EtherType != frame.EtherTypeARP {
				continue
			}
			a, ok := frame.ParseARP(eth.Payload)
			if !ok || a.IsProbe() {
				continue
			}
			// A reply always asserts ownership. A request asserts it only when
			// it is gratuitous - sender and target address equal - which is how
			// a host announces an address rather than asking about one.
			if !a.IsReply() && !a.IsGratuitous() {
				continue
			}
			ip := a.SenderIP.String()
			if claims[ip] == nil {
				claims[ip] = map[string]int{}
			}
			claims[ip][a.SenderMAC.String()]++
		}
	}
}

const (
	vecGatewayChanged    = "arp/gateway-mac-changed"
	vecGatewayShared     = "arp/gateway-mac-shared"
	vecGatewayUnresolved = "arp/gateway-unresolved"
	vecIPConflict        = "arp/ip-conflict"
	vecImpersonation     = "arp/gateway-impersonation"
)

func (Probe) Compare(base, cur probe.Snapshot, cc probe.CompareCtx) []probe.Finding {
	var now snapshot
	if ok, err := cur.Decode(&now); !ok || err != nil {
		return nil
	}
	var prev snapshot
	hasBase, _ := base.Decode(&prev)

	var out []probe.Finding
	add := func(f probe.Finding) {
		f.Probe = name
		if f.Score == 0 {
			f.Score = cc.Weight(f.Vector)
		}
		out = append(out, f)
	}

	target := now.GatewayIP
	if target == "" {
		target = "network"
	}

	// The gateway stopped resolving. Not an attack on its own - a router
	// rebooting looks like this - but the probe is blind until it comes back,
	// and blindness is worth one line rather than silence.
	if now.GatewayMAC == "" {
		if hasBase && prev.GatewayMAC != "" {
			add(probe.Finding{
				Vector: vecGatewayUnresolved, Target: target,
				Title: "Your router stopped answering on the local network",
				Evidence: map[string]string{
					"gateway": now.GatewayIP,
					"was":     prev.GatewayMAC,
					"note":    "this check cannot see a spoof while the address is unresolved",
				},
			})
		}
		return out
	}

	// The signal. Same gateway address, different hardware answering for it.
	//
	// The profile key pins the gateway IP, so reaching here means the sensor is
	// on the same network it was on last time and something else is now
	// claiming to be its router.
	if hasBase && prev.GatewayMAC != "" && prev.GatewayIP == now.GatewayIP &&
		prev.GatewayMAC != now.GatewayMAC {
		add(probe.Finding{
			Vector: vecGatewayChanged, Target: target,
			Title: "Something else is claiming to be your router",
			// A change that must never be absorbed into the baseline: if it
			// were, the attacker's MAC would be the router by the next pass.
			Change:   true,
			Identity: map[string]string{"was": prev.GatewayMAC, "now": now.GatewayMAC},
			Evidence: map[string]string{
				"gateway":     now.GatewayIP,
				"was":         prev.GatewayMAC + vendorHint(prev.GatewayMAC),
				"now":         now.GatewayMAC + vendorHint(now.GatewayMAC),
				"what_to_do":  "if you did not replace your router, disconnect devices you do not recognise and avoid logging in to anything until this clears",
				"benign_case": "this is also what a genuinely replaced or rebooted-into-failover router looks like",
			},
		})
	}

	// What the wire showed. These need capture and are silent at tier 3.
	out = append(out, fromClaims(now, cc)...)

	// A spoofer usually answers for the router while still holding its own
	// address, so the same hardware appears twice in the table. That is very
	// hard to arrange by accident.
	if others := otherIPsFor(now.Neighbors, now.GatewayMAC, now.GatewayIP); len(others) > 0 {
		add(probe.Finding{
			Vector: vecGatewayShared, Target: target,
			Title:    "Another device on your network shares your router's hardware address",
			Identity: map[string]string{"mac": now.GatewayMAC},
			Evidence: map[string]string{
				"gateway":      now.GatewayIP,
				"mac":          now.GatewayMAC + vendorHint(now.GatewayMAC),
				"also_claimed": strings.Join(others, ", "),
				"count":        strconv.Itoa(len(others)),
				"benign_case":  "a router that holds more than one address on the same interface looks like this too",
			},
		})
	}
	return out
}

// fromClaims reports what listening on the wire showed that the neighbour table
// could not.
func fromClaims(now snapshot, cc probe.CompareCtx) []probe.Finding {
	if !now.Captured {
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

	for _, ip := range sortedKeys(now.Claims) {
		macs := now.Claims[ip]
		if len(macs) < 2 {
			continue
		}
		// Two devices asserting the same address, live, in one short window.
		// An address collision from a misconfigured static lease looks like
		// this too - hence the benign note - but it is never routine.
		vec, title := vecIPConflict, "Two devices are claiming the same address on your network"
		if ip == now.GatewayIP {
			vec = vecImpersonation
			title = "Two devices are claiming to be your router"
		}
		add(probe.Finding{
			Vector: vec, Target: ip,
			Identity: map[string]string{"claimants": strings.Join(sortedKeys(macs), ",")},
			Title:    title,
			Evidence: map[string]string{
				"address":     ip,
				"claimed_by":  describeClaims(macs),
				"seen_over":   "one capture window",
				"benign_case": "a duplicate static address, or a device that just changed hardware, looks like this too",
				"what_to_do":  "if this is your router's address, treat the network as untrusted until it clears",
			},
		})
	}
	return out
}

// describeClaims renders "mac (vendor) x N" for each claimant, busiest first -
// a spoofer usually has to shout far more often than the device it is drowning
// out, so the counts are the tell.
func describeClaims(macs map[string]int) string {
	keys := sortedKeys(macs)
	sort.SliceStable(keys, func(i, j int) bool { return macs[keys[i]] > macs[keys[j]] })
	parts := make([]string, 0, len(keys))
	for _, m := range keys {
		parts = append(parts, m+vendorHint(m)+" x"+strconv.Itoa(macs[m]))
	}
	return strings.Join(parts, ", ")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// otherIPsFor lists addresses besides the gateway that resolve to the same MAC.
func otherIPsFor(table map[string]string, mac, gatewayIP string) []string {
	if mac == "" {
		return nil
	}
	var out []string
	for ip, m := range table {
		if m == mac && ip != gatewayIP {
			out = append(out, ip)
		}
	}
	sort.Strings(out)
	return out
}

// vendorHint names the hardware maker when the prefix is one we recognise.
//
// ponytail: a handful of entries, not the 30k-line IEEE OUI registry. The point
// is to make the evidence readable to a person - "your router used to be a
// Synology and now it is a Raspberry Pi" is a sentence someone can act on - not
// to build a device database. Phase 1's inventory probe is where a real OUI
// lookup belongs, if it earns its place there.
var ouiNames = map[string]string{
	"00:11:32": "Synology",
	"b8:27:eb": "Raspberry Pi",
	"dc:a6:32": "Raspberry Pi",
	"e4:5f:01": "Raspberry Pi",
	"28:cd:c1": "Raspberry Pi",
	"2c:cf:67": "Raspberry Pi",
	"00:0c:29": "VMware",
	"00:50:56": "VMware",
	"08:00:27": "VirtualBox",
	"52:54:00": "QEMU/KVM",
}

func vendorHint(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	if v, ok := ouiNames[mac[:8]]; ok {
		return " (" + v + ")"
	}
	// A locally administered address has the second-least-significant bit of
	// the first octet set. Real hardware rarely does; software pretending to be
	// hardware often does.
	if b, err := strconv.ParseUint(mac[:2], 16, 8); err == nil && b&0x02 != 0 {
		return " (randomised or software-assigned address)"
	}
	return ""
}
