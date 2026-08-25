package arpprobe

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// discover nudges every host on the sensor's local IPv4 subnet so the kernel
// resolves them into its neighbour table, turning the device list from "who has
// spoken recently" into a full inventory - the same thing arp-scan, Fing or a
// router's own device page do. It sends one connectionless UDP probe per host,
// which is enough to trigger the ARP resolution beneath it, then waits briefly
// for the replies to land before the caller reads the table.
//
// It is best-effort and silent: an error is just a host that is not there. It
// sends no ARP claims and asserts nothing about any address, so it can never
// trip the arp probe's gateway-impersonation detection - and a device that only
// answers ARP for its own IP (a quiet rogue box) is dragged into the inventory
// exactly because it must answer to be reachable at all.
func discover(ctx context.Context, iface string) {
	hosts, ok := subnetHosts(iface)
	if !ok {
		return
	}
	nudge(ctx, hosts)
	// Let ARP complete before the caller reads the neighbour table.
	select {
	case <-ctx.Done():
	case <-time.After(1500 * time.Millisecond):
	}
}

// subnetHosts returns every host address on iface's IPv4 network, minus the
// network, broadcast and the interface's own address. It refuses a network
// larger than /22 (~1024 hosts): home networks are /24, and a sensor has no
// business blasting a /16.
func subnetHosts(iface string) ([]netip.Addr, bool) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, false
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, false
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.To4() == nil {
			continue
		}
		pfx, err := netip.ParsePrefix(ipn.String())
		if err != nil {
			continue
		}
		return hostsInPrefix(pfx)
	}
	return nil, false
}

// hostsInPrefix enumerates the usable host addresses of an IPv4 prefix, dropping
// the network address, the broadcast address and the interface's own address
// (the prefix's Addr). It refuses anything larger than /22 (~1024 hosts) so a
// misread mask can never turn discovery into a /16 flood.
func hostsInPrefix(pfx netip.Prefix) ([]netip.Addr, bool) {
	if !pfx.Addr().Is4() || pfx.Bits() < 22 {
		return nil, false
	}
	self := pfx.Addr()
	net4 := pfx.Masked()

	var all []netip.Addr
	for ip := net4.Addr(); net4.Contains(ip); ip = ip.Next() {
		all = append(all, ip)
		if len(all) > 4096 { // safety belt; the /22 gate makes this unreachable
			break
		}
	}
	hosts := make([]netip.Addr, 0, len(all))
	for i, ip := range all {
		if i == 0 || i == len(all)-1 { // network, broadcast
			continue
		}
		if ip == self {
			continue
		}
		hosts = append(hosts, ip)
	}
	return hosts, len(hosts) > 0
}

// nudge fires one connectionless UDP probe at each host to prompt ARP
// resolution. Port 9 (discard) is deliberate: the payload is meant to be thrown
// away - only the ARP exchange beneath it matters. Bounded concurrency and a
// hard deadline keep it from ever stalling a pass.
func nudge(ctx context.Context, hosts []netip.Addr) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	d := net.Dialer{Timeout: 400 * time.Millisecond}

	for _, h := range hosts {
		select {
		case <-cctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := d.DialContext(cctx, "udp", net.JoinHostPort(ip, "9"))
			if err != nil {
				return
			}
			c.Write([]byte{0}) //nolint:errcheck // fire-and-forget; the ARP beneath it is the point
			c.Close()          //nolint:errcheck // nothing to do on close error
		}(h.String())
	}
	wg.Wait()
}
