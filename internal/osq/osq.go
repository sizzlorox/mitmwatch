// Package osq queries the operating system for network facts the probes need.
//
// Every function here is best-effort: a field it cannot determine comes back
// empty rather than failing the whole query, and `doctor` reports what was
// missing. A sensor with a partial network identity still runs its canaries.
package osq

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// NetworkIdentity is what makes one network distinguishable from another. It
// keys the baseline profile: change any of these and mitmwatch is on a
// different network and applies a different baseline.
type NetworkIdentity struct {
	Iface      string   `json:"iface"`
	SSID       string   `json:"ssid,omitempty"`
	GatewayIP  string   `json:"gateway_ip"`
	GatewayMAC string   `json:"gateway_mac"`
	DHCPServer string   `json:"dhcp_server,omitempty"`
	Resolvers  []string `json:"resolvers,omitempty"`

	// Missing lists the fields this platform could not determine.
	Missing []string `json:"missing,omitempty"`
}

// Key is the profile identifier.
//
// It deliberately excludes the gateway MAC and the DHCP server address, which
// SDD 7.3 named as inputs. Both are values an on-path attacker chooses
// outright, and keying on them handed the attacker the baseline: spoof the
// gateway MAC and mitmwatch selects a brand-new profile with an empty snapshot
// set and a fresh learning window, in which everything below Critical is
// suppressed. Rotate it each run and the learning window never ends. The
// detector would go quiet in exactly the circumstance it exists for, and the
// louder the attack, the quieter it got.
//
// Worse, it was circular: ARP spoofing IS a gateway-MAC change, so the probe
// meant to catch it could never accumulate a baseline to catch it with.
//
// What remains is what the attacker cannot pick: the interface and the SSID
// are local facts, and the gateway IP is fixed by the network the victim is
// actually on. The cost is that two networks sharing an interface name and
// gateway IP - eth0 via 192.168.1.1 is not rare - now share one profile. A
// shared baseline across similar networks is noise; a baseline the attacker
// can reset is silence. Noise is the better failure.
//
// The gateway MAC is still watched, but as evidence rather than identity: the
// arp probe carries it in its own snapshot, where the baseline-adoption rules
// protect it.
func (n NetworkIdentity) Key() string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		strings.ToLower(n.Iface),
		strings.ToLower(n.SSID),
		n.GatewayIP,
	}, "|")))
	return hex.EncodeToString(h[:8])
}

// Label is a human-readable name for the network, for the dashboard and CLI.
func (n NetworkIdentity) Label() string {
	switch {
	case n.SSID != "":
		return n.SSID
	case n.Iface != "":
		return n.Iface
	default:
		return "unknown network"
	}
}

// Identify collects the current network identity. Implemented per platform.
func Identify(ctx context.Context) (NetworkIdentity, error) {
	return identify(ctx)
}

// run executes a command with a deadline and returns trimmed stdout. Errors
// are returned to the caller, which decides whether the field is optional.
func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return strings.TrimSpace(string(out)), err
}

// normMAC puts a MAC into one canonical form so the same address compares equal
// whatever produced it.
//
// Three platforms, three spellings: Get-NetNeighbor gives "AA-BB-CC-DD-EE-FF",
// /proc/net/arp gives "aa:bb:cc:dd:ee:ff", and macOS arp(8) drops leading zeros
// - "0:11:32:c3:cb:d6". Without padding, the last of those is a different string
// from the first two for the same physical device, which would make a gateway
// MAC look like it changed every time the sensor moved between platforms.
func normMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", ":")
	if s == "" {
		return ""
	}
	parts := strings.Split(s, ":")
	if len(parts) == 6 {
		for i, p := range parts {
			if len(p) == 1 {
				parts[i] = "0" + p
			}
		}
		s = strings.Join(parts, ":")
	}
	// All-zero and broadcast are placeholders, never a real neighbour.
	if s == "00:00:00:00:00:00" || s == "ff:ff:ff:ff:ff:ff" {
		return ""
	}
	return s
}

// Neighbor is one entry of the host's IP-to-MAC table.
type Neighbor struct {
	IP    string `json:"ip"`
	MAC   string `json:"mac"`
	Iface string `json:"iface,omitempty"`
}

// Neighbors returns the resolved entries of the neighbour table.
//
// Incomplete entries are dropped: an address the host asked about and never got
// an answer for says nothing, and including them would make a quiet scan look
// like a table full of devices.
func Neighbors(ctx context.Context) ([]Neighbor, error) {
	ns, err := neighbors(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(ns, func(i, j int) bool { return ns[i].IP < ns[j].IP })
	return ns, nil
}

// missingOf lists the identity fields this platform failed to determine.
func missingOf(n NetworkIdentity) []string {
	var m []string
	for _, f := range []struct {
		name string
		ok   bool
	}{
		{"iface", n.Iface != ""},
		{"gateway_ip", n.GatewayIP != ""},
		{"gateway_mac", n.GatewayMAC != ""},
		{"resolvers", len(n.Resolvers) > 0},
	} {
		if !f.ok {
			m = append(m, f.name)
		}
	}
	return m
}
