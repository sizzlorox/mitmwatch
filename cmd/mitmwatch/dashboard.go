package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
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

// dashboardDevices reads the arp probe's neighbour table out of the profile, so
// the Devices page shows what the sensor has actually seen.
func (e *env) dashboardDevices(ctx context.Context) []web.Device {
	snap, ok := e.profile.Snapshots["arp"]
	if !ok || snap.Empty() {
		return nil
	}
	var s struct {
		Neighbors map[string]string `json:"neighbors"`
	}
	if _, err := snap.Decode(&s); err != nil {
		return nil
	}
	ips := make([]string, 0, len(s.Neighbors))
	for ip := range s.Neighbors {
		ips = append(ips, ip)
	}
	names := e.resolveNames(ctx, ips)

	out := make([]web.Device, 0, len(s.Neighbors))
	for ip, mac := range s.Neighbors {
		// Best name available: the reverse-DNS hostname, else "router" for the
		// gateway, else the manufacturer from the MAC. A device with none of
		// these (an uncommon maker with no hostname) stays unnamed, its MAC in
		// the next column.
		name := names[ip]
		if name == "" {
			if ip == e.net.GatewayIP {
				name = "router"
			} else {
				name = vendorFor(mac)
			}
		}
		out = append(out, web.Device{IP: ip, MAC: mac, Name: name, First: e.profile.FirstSeen})
	}
	// Stable order: by address, numerically where possible.
	sortDevices(out)
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
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && lessIP(d[j].IP, d[j-1].IP); j-- {
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
