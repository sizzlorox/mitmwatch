//go:build darwin

package osq

import (
	"context"
	"regexp"
	"strings"
)

func identify(ctx context.Context) (NetworkIdentity, error) {
	var n NetworkIdentity
	n.Iface, n.GatewayIP = defaultRoute(ctx)
	if n.GatewayIP != "" {
		n.GatewayMAC = arpLookup(ctx, n.GatewayIP)
	}
	n.Resolvers = scutilDNS(ctx)
	n.SSID = ssid(ctx)
	// ponytail: DHCP server via `ipconfig getpacket <if>` is available but the
	// output format is undocumented; the phase 1 `dhcp` probe reads it off the
	// wire instead.
	n.Missing = missingOf(n)
	return n, nil
}

func defaultRoute(ctx context.Context) (iface, gw string) {
	out, err := run(ctx, "netstat", "-rn", "-f", "inet")
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[0] == "default" {
			return f[len(f)-1], f[1]
		}
	}
	return "", ""
}

func arpLookup(ctx context.Context, ip string) string {
	out, err := run(ctx, "arp", "-n", ip)
	if err != nil {
		return ""
	}
	// e.g. "? (192.168.1.1) at a4:2b:8c:1d:2e:3f on en0 ifscope [ethernet]"
	m := regexp.MustCompile(`at ([0-9a-fA-F:]{11,17}) on`).FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	return normMAC(m[1])
}

func scutilDNS(ctx context.Context) []string {
	out, err := run(ctx, "scutil", "--dns")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var res []string
	for _, m := range regexp.MustCompile(`(?m)^\s*nameserver\[\d+\]\s*:\s*(\S+)`).FindAllStringSubmatch(out, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			res = append(res, m[1])
		}
	}
	return res
}

func ssid(ctx context.Context) string {
	// Recent macOS requires sudo for BSSID but still reports SSID here.
	out, err := run(ctx, "wdutil", "info")
	if err != nil {
		return ""
	}
	m := regexp.MustCompile(`(?m)^\s*SSID\s*:\s*(.+)$`).FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	s := strings.TrimSpace(m[1])
	if s == "None" || s == "<redacted>" {
		return ""
	}
	return s
}

// neighbors parses arp(8). Lines look like:
//
//	? (10.0.4.1) at 0:11:32:c3:cb:d6 on en0 ifscope [ethernet]
//
// Note the unpadded octets - normMAC exists for this.
func neighbors(ctx context.Context) ([]Neighbor, error) {
	out, err := run(ctx, "arp", "-an")
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`\(([0-9.]+)\) at ([0-9a-fA-F:]{11,17})(?: on (\S+))?`)
	var ns []Neighbor
	for _, m := range re.FindAllStringSubmatch(out, -1) {
		mac := normMAC(m[2])
		if mac == "" {
			continue
		}
		ns = append(ns, Neighbor{IP: m[1], MAC: mac, Iface: m[3]})
	}
	return ns, nil
}
