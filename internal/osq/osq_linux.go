//go:build linux

package osq

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"os"
	"strconv"
	"strings"
)

func identify(ctx context.Context) (NetworkIdentity, error) {
	var n NetworkIdentity
	n.Iface, n.GatewayIP = defaultRoute()
	if n.GatewayIP != "" {
		n.GatewayMAC = arpLookup(n.GatewayIP)
	}
	n.Resolvers = resolvConf()
	if n.Iface != "" {
		n.SSID = ssid(ctx, n.Iface)
	}
	// ponytail: no DHCP server field on linux in phase 0. Lease-file locations
	// vary by dhcpcd/dhclient/NetworkManager/systemd-networkd; the `dhcp` probe
	// in phase 1 gets it from the wire instead, which is more trustworthy anyway.
	n.Missing = missingOf(n)
	return n, nil
}

// defaultRoute parses /proc/net/route for the lowest-metric default route.
func defaultRoute() (iface, gw string) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", ""
	}
	defer f.Close()

	best := -1
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 || fields[1] != "00000000" {
			continue
		}
		metric, err := strconv.Atoi(fields[6])
		if err != nil {
			continue
		}
		if best >= 0 && metric >= best {
			continue
		}
		// Gateway is little-endian hex.
		v, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil {
			continue
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, uint32(v))
		best, iface, gw = metric, fields[0], ip.String()
	}
	return iface, gw
}

func arpLookup(ip string) string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 4 && fields[0] == ip {
			return normMAC(fields[3])
		}
	}
	return ""
}

func resolvConf() []string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "nameserver "); ok {
			if s := strings.TrimSpace(after); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func ssid(ctx context.Context, iface string) string {
	// Wireless interfaces expose this directory; skip the exec for wired ones.
	if _, err := os.Stat("/sys/class/net/" + iface + "/wireless"); err != nil {
		return ""
	}
	if out, err := run(ctx, "iwgetid", "-r"); err == nil && out != "" {
		return out
	}
	out, err := run(ctx, "iw", "dev", iface, "link")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		if after, ok := strings.CutPrefix(strings.TrimSpace(line), "SSID: "); ok {
			return strings.TrimSpace(after)
		}
	}
	return ""
}

// neighbors parses the whole of /proc/net/arp.
//
//	IP address  HW type  Flags  HW address         Mask  Device
//	10.0.4.1    0x1      0x2    00:11:32:c3:cb:d6  *     eth0
//
// Flags is a bitmask; ATF_COM (0x2) means the entry is complete. An entry
// without it is an unanswered query, not a device.
func neighbors(_ context.Context) ([]Neighbor, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Neighbor
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(fields[2], "0x"), 16, 32)
		if err != nil || flags&0x2 == 0 {
			continue
		}
		mac := normMAC(fields[3])
		if mac == "" {
			continue
		}
		out = append(out, Neighbor{IP: fields[0], MAC: mac, Iface: fields[5]})
	}
	return out, sc.Err()
}
