package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/core/baseline"
)

// recordDeviceHistory folds this cycle's neighbour table into the profile's
// device history.
//
// Two things about where it reads from matter more than they look.
//
// It reads the snapshot the arp probe just *observed*, not the one in the
// baseline. The baseline deliberately refuses to adopt a snapshot that reports
// an unabsorbed change - which is exactly what an ARP spoof produces - so the
// stored snapshot at that moment is the world as it was before the attack
// began. Recording from it would stamp "seen just now" on the pre-attack device
// set on the very cycle an attacker appeared, and never record the attacker at
// all.
//
// And it does nothing at all unless the arp probe both ran this cycle and
// managed to observe. A neighbour table that could not be read is not an empty
// network; treating it as one would let a failed read erase the history.
func (e *env) recordDeviceHistory(ctx context.Context, now time.Time) {
	if e.erroredThisPass["arp"] {
		return
	}
	snap, ok := e.observedThisPass["arp"]
	if !ok || snap.Empty() {
		return
	}
	var s struct {
		Neighbors map[string]string `json:"neighbors"`
	}
	if _, err := snap.Decode(&s); err != nil || len(s.Neighbors) == 0 {
		return
	}

	// Fold addresses onto hardware: one device that has moved across a DHCP
	// lease is one device, and the neighbour table keys the other way round.
	byMAC := map[string][]string{}
	ips := make([]string, 0, len(s.Neighbors))
	for ip, mac := range s.Neighbors {
		if !unicastMAC(mac) {
			continue
		}
		byMAC[mac] = append(byMAC[mac], ip)
		ips = append(ips, ip)
	}
	names := e.resolveNames(ctx, ips)

	clients, servers := e.dhcpIdentities()
	seen := make([]baseline.Device, 0, len(byMAC))
	for mac, addrs := range byMAC {
		sortIPs(addrs)
		dev := baseline.Device{
			MAC:    mac,
			Addrs:  addrs,
			Name:   e.deviceName(addrs[0], mac, names[addrs[0]]),
			Random: randomMAC(mac),
		}
		if c, ok := clients[mac]; ok {
			dev.Hostname, dev.VendorClass, dev.ParamList = c.Hostname, c.VendorClass, c.ParamList
		}
		dev.DHCPServer = servers[mac]
		seen = append(seen, dev)
	}

	e.announceNewDevices(now, seen)
	if e.profile.RecordDevices(now, seen) {
		// Capacity pressure is not a housekeeping detail to swallow: a burst of
		// hardware addresses large enough to fill the history is itself worth
		// seeing, and a record that quietly drops what it cannot hold is hiding
		// the very thing that filled it.
		e.addEvent(baseline.Event{
			When: now, Kind: "system",
			Text: "A lot of new hardware addresses appeared at once - the device history is at capacity",
		})
	}
	e.lastCycle = now
}

// deviceName is the one place device labelling is decided: the reverse-DNS
// hostname, else "router" for the gateway, else the manufacturer from the MAC.
// A device with none of those stays unnamed and is shown by its address.
//
// Cosmetic, always. A name never reaches any Compare - a resolver that lies
// mislabels a row and nothing more, and a lying local resolver is what the dns
// probe exists to catch.
func (e *env) deviceName(ip, mac, resolved string) string {
	if resolved != "" {
		return resolved
	}
	if ip != "" && ip == e.net.GatewayIP {
		return "router"
	}
	return vendorFor(mac)
}

// deviceLabel turns an alert target into something a person recognises, using
// the device history: "workshop-pc" rather than "fe80::c0a8:1ff:fe24:9b31".
//
// mac is the hardware address the finding reported, when it had one. It is the
// only way the link-local half of a dual-stack device can ever be named: the
// device history is built from the neighbour table, which on Linux is
// /proc/net/arp and therefore IPv4 only, so an alert about fe80:: matches
// nothing by address. The finding itself saw the ethernet header and knows the
// hardware, and that hardware is in the history under its IPv4 address.
//
// The target may be an address, a hostname or "network". An unmatched target
// comes back as it went in - guessing would be worse than a raw address,
// because a wrong name on an alert sends someone to unplug the wrong machine.
func (e *env) deviceLabel(target, mac string) string {
	if target == "" || e.profile == nil {
		return target
	}
	if target == e.net.GatewayIP {
		return "router (" + target + ")"
	}
	for _, d := range e.profile.Devices {
		for _, a := range d.Addrs {
			if a == target {
				return nameOr(d, target)
			}
		}
	}
	// Nothing matched by address. Fall back to the hardware the finding
	// reported, but only to a record that already exists - never to a MAC
	// parsed or guessed out of evidence.
	if d, ok := e.profile.Devices[mac]; ok {
		return nameOr(d, target)
	}
	return target
}

func nameOr(d baseline.Device, target string) string {
	if d.Name != "" {
		return d.Name + " (" + target + ")"
	}
	return target + " · " + d.MAC
}

// unicastMAC reports whether a hardware address belongs to a device at all.
//
// The neighbour table carries more than devices. Windows' own query returns the
// multicast pseudo-entries for 224.0.0.251 and friends as 01-00-5E-* rows, and
// IPv6 multicast maps onto 33-33-*. osq.normMAC drops only the all-zero and
// broadcast placeholders, which is right for the arp probe - its findings are
// about claims, and it should see every claim - but a device *history* keyed on
// those would grow four permanent phantom devices that never leave.
//
// Deliberately here and not in osq: changing normMAC would change the arp
// probe's persisted snapshot and its findings, which this has no business doing.
func unicastMAC(mac string) bool {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if len(mac) < 17 {
		return false
	}
	switch mac {
	case "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff":
		return false
	}
	// The group bit, least significant of the first octet: set means multicast,
	// which is a destination, never a sender.
	b := hexNibblePair(mac[0:2])
	return b >= 0 && b&0x01 == 0
}

// randomMAC reports a locally administered address - the private, rotating kind
// modern phones use. The history is then of the address, not of the device, and
// the page has to say so rather than claim a life the record cannot have.
func randomMAC(mac string) bool {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if len(mac) < 2 {
		return false
	}
	b := hexNibblePair(mac[0:2])
	return b >= 0 && b&0x02 != 0
}

func sortIPs(ips []string) {
	for i := 1; i < len(ips); i++ {
		for j := i; j > 0 && lessIP(ips[j], ips[j-1]); j-- {
			ips[j], ips[j-1] = ips[j-1], ips[j]
		}
	}
}

// maxNewDeviceEvents bounds how many arrivals one cycle logs individually. A
// flood of invented hardware addresses is exactly what an attacker on the
// segment can produce, and must not be able to push real history out of the
// log; the overflow is summarised, not dropped.
const maxNewDeviceEvents = 5

// announceNewDevices logs each hardware address the history has not seen
// before, with enough in the entry for the dashboard to open a page about it.
//
// Silent on an empty history: the first cycle on a network would otherwise
// report the whole household as newly arrived.
func (e *env) announceNewDevices(now time.Time, seen []baseline.Device) {
	if len(e.profile.Devices) == 0 {
		return
	}
	var fresh []baseline.Device
	for _, d := range seen {
		if _, known := e.profile.Devices[d.MAC]; !known {
			fresh = append(fresh, d)
		}
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].MAC < fresh[j].MAC })
	for i, d := range fresh {
		if i == maxNewDeviceEvents {
			e.addEvent(baseline.Event{
				When: now, Kind: "system",
				Text: fmt.Sprintf("%d more new devices appeared in the same cycle", len(fresh)-i),
			})
			break
		}
		label := d.Name
		if label == "" && len(d.Addrs) > 0 {
			label = d.Addrs[0]
		}
		if label == "" {
			label = d.MAC
		}
		ev := baseline.Event{
			When: now, Kind: "device", Target: d.MAC, Device: label,
			Text:     "New device on the network",
			Evidence: map[string]string{"Hardware address": d.MAC},
		}
		if len(d.Addrs) > 0 {
			ev.Evidence["Addresses"] = strings.Join(d.Addrs, ", ")
		}
		e.addEvent(ev)
	}
}

// dhcpClient is what a client said about itself in DHCP.
type dhcpClient struct{ Hostname, VendorClass, ParamList string }

// dhcpIdentities reads the dhcp probe's observation for who said what, and
// which hardware addresses have answered as a server. Empty when the probe did
// not observe this pass; absence is not evidence either way.
func (e *env) dhcpIdentities() (map[string]dhcpClient, map[string]bool) {
	clients, servers := map[string]dhcpClient{}, map[string]bool{}
	if e.erroredThisPass["dhcp"] {
		return clients, servers
	}
	snap, ok := e.observedThisPass["dhcp"]
	if !ok || snap.Empty() {
		return clients, servers
	}
	var s struct {
		Clients map[string]struct {
			Hostname    string `json:"hostname"`
			VendorClass string `json:"vendor_class"`
			ParamList   string `json:"param_list"`
		} `json:"clients"`
		Servers map[string]struct {
			MAC string `json:"mac"`
		} `json:"servers"`
	}
	if _, err := snap.Decode(&s); err != nil {
		return clients, servers
	}
	for mac, c := range s.Clients {
		clients[strings.ToLower(mac)] = dhcpClient{c.Hostname, c.VendorClass, c.ParamList}
	}
	for _, sv := range s.Servers {
		if sv.MAC != "" {
			servers[strings.ToLower(sv.MAC)] = true
		}
	}
	return clients, servers
}
