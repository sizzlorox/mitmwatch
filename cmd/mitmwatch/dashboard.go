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

	"github.com/sizzlorox/mitmwatch/internal/core/verdict"
	"github.com/sizzlorox/mitmwatch/internal/probe"
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
			Present: !e.lastCycle.IsZero() && d.LastSeen.Equal(e.lastCycle),
			Random:  d.Random,
			Addrs:   d.Addrs,
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
