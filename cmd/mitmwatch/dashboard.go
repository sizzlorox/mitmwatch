package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/core/baseline"
	"github.com/sizzlorox/mitmwatch/internal/core/verdict"
	"github.com/sizzlorox/mitmwatch/internal/probe"
	"github.com/sizzlorox/mitmwatch/internal/probe/pathprobe"
	"github.com/sizzlorox/mitmwatch/internal/web"
)

// area maps each probe to one of the six plain-language cards. A person does
// not think in terms of "the arp probe"; they think "is my router okay". The
// grouping is what turns a list of vectors into that question.
var probeArea = map[string]string{
	"arp":        "router",
	"dhcp":       "router",
	"nd":         "router",
	"nameres":    "devices",
	"tls":        "tls",
	"sslstrip":   "tls",
	"truststore": "tls",
	"dns":        "dns",
	"clock":      "outside",
}

var areaNames = map[string]string{
	"router":  "Your router",
	"wifi":    "Your Wi-Fi",
	"dns":     "Website lookups",
	"tls":     "Secure connections",
	"devices": "Devices",
	"outside": "Outside check",
}

var areaClear = map[string]string{
	"router":  "Nothing is impersonating your router.",
	"wifi":    "Not being watched yet.",
	"dns":     "Website lookups match an independent source.",
	"tls":     "Secure sites look the same here as everywhere.",
	"devices": "No device is answering for names that are not its own.",
	"outside": "The clock and the wider internet look normal.",
}

// buildAreas turns this cycle's findings into the six cards.
// couldNotCheck names the Info-band vectors that mean "this check could not
// run", as opposed to Info-band findings that are simply routine (a certificate
// rotating). Only the former should grey a card to "unknown"; the latter must
// leave it green, or a household sees amber over something that happens daily.
var couldNotCheck = map[string]bool{
	"arp/gateway-unresolved":       true,
	"truststore/unreadable":        true,
	"tls/handshake-failed":         true,
	"tls/system-store-unavailable": true,
	"dns/doh-unreachable":          true,
	"sslstrip/host-unsuitable":     true,
	"witness/unreachable":          true,
}

func buildAreas(alerts, held []verdict.Alert, learning bool) []web.Area {
	worst := map[string]verdict.Band{}
	seen := map[string]bool{}
	line := map[string]string{}
	note := func(as []verdict.Alert) {
		for _, a := range as {
			for _, f := range a.Findings {
				key := probeArea[f.Probe]
				if key == "" {
					key = "outside"
				}
				// A routine Info finding (a rotated leaf) does not change a
				// card at all - it is not something to look at. Only a Low+
				// finding, or an Info "could not check" one, moves the card.
				band := a.Band
				if band < verdict.Low && !couldNotCheck[f.Vector] {
					continue
				}
				if !seen[key] || band > worst[key] {
					seen[key] = true
					worst[key] = band
					line[key] = f.Title
				}
			}
		}
	}
	note(alerts)
	note(held)

	areas := make([]web.Area, 0, len(areaNames))
	for key, human := range areaNames {
		a := web.Area{Key: key, Name: human, State: "ok", Line: areaClear[key]}
		if key == "wifi" {
			a.State, a.Line = "unknown", "Wi-Fi monitoring is not built yet."
		}
		if seen[key] {
			switch b := worst[key]; {
			case b >= verdict.Medium:
				a.State = "attention"
			case b >= verdict.Low:
				a.State = "learning" // amber, not alarming
			default:
				// Info: the check could not run. "unknown", not "attention" -
				// "could not check" must not read as "under attack".
				a.State = "unknown"
			}
			a.Line = line[key]
		} else if learning && key != "wifi" {
			a.State, a.Line = "learning", "Still learning what is normal here."
		}
		areas = append(areas, a)
	}
	return areas
}

// serveDashboard starts the read-only dashboard on the LAN.
//
// Bound to the configured interfaces, never 0.0.0.0 blindly: a status page that
// says whether your network is compromised should not be reachable from the
// internet by default. Plain HTTP on the LAN is deliberate - a self-signed
// certificate would train the household to click through the exact warning this
// tool exists to make them heed, and a locally generated CA is precisely what
// the truststore probe flags.
func serveDashboard(ctx context.Context, addr string, state *web.State) (*http.Server, error) {
	if addr == "" {
		addr = ":8080"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Handler:           web.Handler(state),
		ReadHeaderTimeout: 5 * time.Second,
		// A slow or stuck client must not tie up a connection forever. The
		// handlers already render under the lock and write after releasing it,
		// so a stalled write cannot block the sensor - this bounds the leak of
		// the connection itself.
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(sh) //nolint:errcheck // shutting down anyway
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Println("dashboard:", err)
		}
	}()
	return srv, nil
}

// dashboardDevices renders the stored device history, one row per hardware
// address.
//
// It reads the history rather than the live neighbour table because the table
// cannot answer the question a person actually has. The table holds what this
// host has resolved right now, so a device that was here yesterday and is
// switched off today is simply missing from it - indistinguishable from one
// that was never here at all. Present marks the ones seen in the last completed
// cycle; the rest are shown with when they were last around.
func (e *env) dashboardDevices() []web.Device {
	hist := e.profile.DeviceList()
	out := make([]web.Device, 0, len(hist))
	for _, d := range hist {
		a := e.assessDevice(d, hist)
		ip := ""
		if len(d.Addrs) > 0 {
			ip = d.Addrs[0]
		}
		out = append(out, web.Device{
			IP: ip, MAC: d.MAC, Name: d.Name,
			FirstSeen: d.FirstSeen, LastSeen: d.LastSeen,
			// "Present" is "seen in the cycle that produced this page", not
			// "seen recently": the sensor stamps every sighting with the same
			// cycle time, so the comparison is exact rather than a window.
			Present:     !e.lastCycle.IsZero() && d.LastSeen.Equal(e.lastCycle),
			Random:      d.Random,
			Addrs:       d.Addrs,
			Vendor:      vendorFor(d.MAC),
			Cycles:      d.Cycles,
			Established: d.Established,
			Notes:       a.Notes, Looks: a.Looks, Verdict: a.Verdict,
			VerdictClass: a.Class, Behaviour: a.Behaviour,
		})
	}
	// Stable order: connected first, then by address, numerically where
	// possible, so the list does not reshuffle between page loads.
	sortDevices(out)
	return out
}

func dashboardChecks(local map[string]auditCheck, outside probe.WitnessView) []web.CheckTiming {
	var checks []web.CheckTiming
	names := make([]string, 0, len(local))
	for name := range local {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		check := local[name]
		checks = append(checks, web.CheckTiming{
			Vantage: "Inside", Check: name, Duration: check.duration,
			Status: check.status, When: check.when,
		})
	}
	names = names[:0]
	for name := range outside.CheckTimes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		status := outside.CheckStatus[name]
		if status == "" {
			status = "complete"
		}
		checks = append(checks, web.CheckTiming{
			Vantage: "Outside", Check: name, Duration: outside.CheckTimes[name],
			Status: status, When: outside.ObservedAt,
		})
	}
	return checks
}

// dashboardPaths turns the sensor's own route traces (inside) and the witness's
// (outside) into the dashboard's drawable form.
func dashboardPaths(inside probe.Snapshot, outside probe.WitnessView) []web.PathView {
	var out []web.PathView
	add := func(vantage string, paths []pathprobe.Path) {
		for _, p := range paths {
			v := web.PathView{Vantage: vantage, Target: p.Target, Reached: p.Reached}
			for _, h := range p.Hops {
				v.Hops = append(v.Hops, web.PathHop{
					TTL: h.TTL, Addr: h.Addr, Class: pathprobe.Class(h.Addr, h.TTL), Delay: h.RTT,
				})
			}
			out = append(out, v)
		}
	}
	add("Inside", pathprobe.Decode(inside))
	if snap, ok := outside.Snapshot("path"); ok {
		add("Outside", pathprobe.Decode(snap))
	}
	return out
}

func (e *env) dashboardFindings(alerts, held []verdict.Alert) []web.AuditFinding {
	var out []web.AuditFinding
	appendAlerts := func(as []verdict.Alert, isHeld bool) {
		for _, alert := range as {
			for _, finding := range alert.Findings {
				target := finding.Target
				if target == "" {
					target = alert.Target
				}
				vantage := "Inside"
				if strings.Contains(finding.Vector, "witness") || finding.Probe == "witness" {
					vantage = "Outside"
				}
				out = append(out, web.AuditFinding{
					Device: e.deviceLabel(target, finding.Evidence["hardware"]),
					Target: target, Vantage: vantage, Check: finding.Probe,
					Severity: alert.Band.String(), Title: finding.Title,
					Held: isHeld, Evidence: finding.Evidence,
				})
			}
		}
	}
	appendAlerts(alerts, false)
	appendAlerts(held, true)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Device != out[j].Device {
			return out[i].Device < out[j].Device
		}
		if out[i].Check != out[j].Check {
			return out[i].Check < out[j].Check
		}
		return out[i].Title < out[j].Title
	})
	return out
}

// nameEntry is one cached reverse-DNS result with its age.
type nameEntry struct {
	name string
	at   time.Time
}

const nameTTL = 30 * time.Minute

// resolveNames labels devices by their reverse-DNS (PTR) name, which on a home
// network is the DHCP hostname the router hands back - "Johns-iPhone", "printer"
// and so on. Results are cached, and looked up concurrently under one short
// deadline so a slow or absent resolver never stalls the sensor cycle.
//
// This is cosmetic only. A device name is never used in any detection: a
// resolver that lies mislabels a row and nothing more, and a lying local
// resolver is exactly what the dns probe exists to catch. It deliberately uses
// the system resolver (the router), because that is the one thing that knows the
// local names - unlike the pinned comparison channels, which must not.
func (e *env) resolveNames(ctx context.Context, ips []string) map[string]string {
	if e.nameCache == nil {
		e.nameCache = map[string]nameEntry{}
	}
	out := make(map[string]string, len(ips))
	var todo []string
	for _, ip := range ips {
		if c, ok := e.nameCache[ip]; ok && time.Since(c.at) < nameTTL {
			out[ip] = c.name
			continue
		}
		todo = append(todo, ip)
	}
	if len(todo) == 0 {
		return out
	}

	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		res net.Resolver
		sem = make(chan struct{}, 8)
	)
	for _, ip := range todo {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			name := ""
			if names, err := res.LookupAddr(rctx, ip); err == nil && len(names) > 0 {
				name = cleanHost(names[0])
			}
			mu.Lock()
			out[ip] = name
			e.nameCache[ip] = nameEntry{name: name, at: time.Now()}
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return out
}

// cleanHost turns a PTR answer into a short label: no trailing dot, and just the
// first component, so "Johns-iPhone.lan." becomes "Johns-iPhone".
func cleanHost(ptr string) string {
	h := strings.TrimSuffix(ptr, ".")
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	return h
}

func sortDevices(d []web.Device) {
	less := func(a, b web.Device) bool {
		if a.Present != b.Present {
			return a.Present
		}
		return lessIP(a.IP, b.IP)
	}
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && less(d[j], d[j-1]); j-- {
			d[j], d[j-1] = d[j-1], d[j]
		}
	}
}

func lessIP(a, b string) bool {
	ap, aerr := net.ParseIP(a), 0
	bp, berr := net.ParseIP(b), 0
	if ap == nil {
		aerr = 1
	}
	if bp == nil {
		berr = 1
	}
	if aerr != berr {
		return aerr < berr
	}
	if ap != nil && bp != nil {
		return strings.Compare(string(ap.To16()), string(bp.To16())) < 0
	}
	return a < b
}

// probeAreasForDoctor is unused by the dashboard but keeps the area map honest:
// every registered probe must map to a card, or its findings vanish from the
// summary. Called from a test.
func unmappedProbes() []string {
	var out []string
	for _, p := range probe.All() {
		if _, ok := probeArea[p.Name()]; !ok {
			out = append(out, p.Name())
		}
	}
	return out
}

// webState aliases web.State so cmd/main can hold a handle without importing
// the web package at its declaration site.
type webState = web.State

// dashboardHost turns a listen address into something clickable.
func dashboardHost(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "<this-device>" + addr
	}
	return addr
}

// deviceAssessment is the read on one device: what it looks like, what it has
// been seen doing, and a hedged verdict with the reasons. Observations only; it
// never scores and no Compare reads it.
type deviceAssessment struct {
	Looks     string
	Verdict   string
	Class     string
	Behaviour []string
	Notes     []string
}

func (e *env) assessDevice(d baseline.Device, all []baseline.Device) deviceAssessment {
	var a deviceAssessment
	var warns []string
	vendor := vendorFor(d.MAC)
	family := dhcpFamily(d)

	// What it looks like: vendor, then the system its DHCP behaviour points to.
	var looks []string
	if vendor != "" {
		looks = append(looks, "made by "+vendor)
	}
	if family != "" {
		looks = append(looks, "behaves like "+family)
	}
	if d.VendorClass != "" {
		looks = append(looks, "DHCP vendor class \""+d.VendorClass+"\"")
	}
	if len(looks) > 0 {
		a.Looks = strings.Join(looks, "; ")
	}

	if vendor != "" {
		a.Notes = append(a.Notes, "The hardware address belongs to "+vendor+".")
	} else if d.Random {
		a.Notes = append(a.Notes, "The hardware address is randomised, as phones and laptops do for privacy, so it names no manufacturer. Identify it by name, or by checking which of your devices has \"private Wi-Fi address\" switched on.")
	} else {
		a.Notes = append(a.Notes, "The manufacturer of this hardware address is not recognised, so it cannot be identified from the address alone. Compare it with the devices you own.")
	}

	// Network behaviour.
	if d.Hostname != "" || d.VendorClass != "" || d.ParamList != "" {
		line := "Asked for an address by DHCP"
		if d.Hostname != "" {
			line += ", calling itself \"" + d.Hostname + "\""
		}
		a.Behaviour = append(a.Behaviour, line+".")
		if d.ParamList != "" {
			a.Behaviour = append(a.Behaviour, "Requested DHCP options in this order: "+d.ParamList+" (the order identifies the network stack).")
		}
	} else {
		a.Behaviour = append(a.Behaviour, "Has not been seen asking for an address by DHCP, so it said nothing about itself. It may use a fixed address, or the sensor has not watched a lease renewal yet.")
	}
	if d.DHCPServer {
		if e.net.GatewayMAC != "" && strings.EqualFold(d.MAC, e.net.GatewayMAC) {
			a.Behaviour = append(a.Behaviour, "Hands out DHCP leases - expected, as it is the router.")
		} else {
			warns = append(warns, "It has answered DHCP requests but is not the router. A second DHCP server can steer every device that trusts it - that is how a rogue server intercepts traffic.")
		}
	}

	if vendorContradicts(vendor, family) {
		warns = append(warns, "Its hardware says "+vendor+" but its DHCP behaviour looks like "+family+", which that maker does not sell. That can mean a forged hardware address - or an ordinary device with a replaced network card or a virtual machine.")
	}
	if d.Hostname != "" && len(d.Addrs) > 0 {
		for _, o := range all {
			if o.MAC != d.MAC && o.Hostname != "" && strings.EqualFold(o.Hostname, d.Hostname) {
				warns = append(warns, "Another hardware address ("+o.MAC+") uses the same hostname \""+d.Hostname+"\". A new address reusing a known name is how an impersonator looks - and how a phone that rotated its address looks.")
				break
			}
		}
	}

	for _, ad := range d.Addrs {
		if ad == e.net.GatewayIP && e.net.GatewayMAC != "" && !strings.EqualFold(d.MAC, e.net.GatewayMAC) {
			warns = append(warns, "It answers on the router's address ("+ad+"), but the router's hardware address is "+e.net.GatewayMAC+". That is what ARP spoofing looks like.")
		}
		for _, o := range all {
			if o.MAC == d.MAC || len(o.Addrs) == 0 || len(d.Addrs) == 0 {
				continue
			}
			if o.Addrs[0] == ad && d.Addrs[0] == ad {
				warns = append(warns, ad+" is currently claimed by another hardware address, "+o.MAC+". Two devices on one address is a conflict or a spoof.")
			}
		}
	}
	if len(d.Addrs) > 2 {
		a.Notes = append(a.Notes, "It has answered on several addresses, which is normal after DHCP lease changes but also what an impersonator hopping addresses looks like.")
	}
	if !d.Established {
		a.Notes = append(a.Notes, "It has not been around long enough to count as part of the household yet.")
	}

	if len(warns) > 0 {
		lead := make([]string, 0, len(warns)+len(a.Notes))
		for _, w := range warns {
			lead = append(lead, "WARNING: "+w)
		}
		a.Notes = append(lead, a.Notes...)
	}

	identified := d.Hostname != "" || family != "" || vendor != ""
	switch {
	case len(warns) > 0:
		a.Class, a.Verdict = verdictSuspicious, "Suspicious - something above does not add up. Check it against your router's client list before trusting it."
	case d.Established && identified:
		a.Class, a.Verdict = verdictKnown, "Probably one of yours - it has been here a while and identifies itself consistently. Not proof: a forged device can do the same."
	default:
		a.Class, a.Verdict = verdictUnverified, "Unverified - not enough is known to say what this is. Find it in your router's client list; if you do not recognise it, treat it as unknown."
	}
	return a
}
