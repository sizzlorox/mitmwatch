// Package web serves the status dashboard.
//
// The dashboard is the product for people who did not install the sensor. Its
// first job is to answer "is my network okay right now?" in one glance, its
// second to tell a non-technical person what to do when it is not.
//
// It loads nothing from the internet. A man-in-the-middle detector that pulled
// its own JavaScript from a CDN would undermine its premise, and the page has
// to render when the internet is exactly what is broken. Everything - the CSS,
// the tiny amount of script - is inline and served from the binary.
package web

import (
	"bytes"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/core/verdict"
)

//go:embed templates/*.html
var files embed.FS

// State is the read model the dashboard renders. The sensor updates it after
// each cycle; the handlers only read. Keeping the render side read-only means a
// page load can never block a probe.
type State struct {
	mu sync.RWMutex

	network   string
	profile   string
	trust     string
	learning  time.Duration
	lastCheck time.Time
	alerts    []verdict.Alert
	held      []verdict.Alert
	areas     map[string]Area
	devices   []Device
	tier      string
	witness   WitnessCard
	since     time.Time
	events    []Event
}

// WitnessCard is the live health of the outside vantage point, for the facts
// strip. Configured but not Connected renders differently from not configured
// at all - a witness that should be there and is not is worth seeing.
type WitnessCard struct {
	Configured bool
	Connected  bool
	Addr       string
	LastSeen   time.Time
}

// Event is one entry in the activity log: an alert raised or cleared, a
// learning window finishing, the witness link coming or going. The log is a
// human-readable memory of what changed, so a glance answers "what happened
// while I was away".
type Event struct {
	When time.Time
	Kind string // "alert" | "clear" | "system"
	Text string
}

// Area is one of the plain-language sections: the router, the Wi-Fi, and so on.
type Area struct {
	Key   string
	Name  string
	State string // "ok" | "attention" | "learning" | "unknown"
	Line  string
}

// Device is one host seen on the network.
type Device struct {
	IP    string
	MAC   string
	Name  string
	First time.Time
}

// NewState returns an empty state that renders as "starting up" rather than
// blank.
func NewState() *State {
	return &State{areas: map[string]Area{}, trust: "unknown", network: "starting up"}
}

// Update replaces the read model. Called once per sensor cycle.
func (s *State) Update(u Update) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.network = u.Network
	s.profile = u.Profile
	s.trust = u.Trust
	s.learning = u.Learning
	s.lastCheck = u.When
	s.alerts = u.Alerts
	s.held = u.Held
	s.devices = u.Devices
	s.tier = u.Tier
	s.witness = u.Witness
	s.since = u.Since
	s.events = u.Events
	s.areas = map[string]Area{}
	for _, a := range u.Areas {
		s.areas[a.Key] = a
	}
}

// Update is what the sensor hands the dashboard each cycle.
type Update struct {
	Network  string
	Profile  string
	Trust    string
	Learning time.Duration
	When     time.Time
	Alerts   []verdict.Alert
	Held     []verdict.Alert
	Areas    []Area
	Devices  []Device
	Tier     string
	Witness  WitnessCard
	Since    time.Time
	Events   []Event
}

// overall is the one-sentence, one-colour verdict at the top of the page.
func (s *State) overall() (state, sentence string) {
	worst := verdict.Info
	for _, a := range s.alerts {
		if a.Band > worst {
			worst = a.Band
		}
	}
	switch {
	case s.lastCheck.IsZero():
		return "unknown", "Starting up - the first check has not finished yet"
	case worst >= verdict.High:
		return "attention", "Something needs your attention"
	case worst >= verdict.Low:
		// Low and Medium: worth surfacing, but not "something is wrong". A
		// routine certificate rotation is Info and must never reach here - it
		// is not unusual, it is Tuesday.
		return "attention", "Something looks unusual"
	case s.learning > 0:
		return "learning", fmt.Sprintf("Getting to know your network - %s left", round(s.learning))
	default:
		// Info-band findings (a rotated leaf, a check that could not run) do
		// not change the headline: the network is fine, and the details are
		// still listed below for anyone who looks.
		return "ok", "All clear"
	}
}

// Handler builds the HTTP handler for the dashboard.
func Handler(s *State) http.Handler {
	tpl := template.Must(template.New("").Funcs(template.FuncMap{
		"upper":   strings.ToUpper,
		"icon":    areaIcon,
		"favicon": favicon,
		"since": func(t time.Time) string {
			if t.IsZero() {
				return "never"
			}
			return round(time.Since(t)) + " ago"
		},
	}).ParseFS(files, "templates/*.html"))

	mux := http.NewServeMux()

	// render does all template work under the read lock into a buffer, then
	// releases the lock before writing to the client.
	//
	// This is the invariant the package comment promises: a page load can never
	// block a probe. Holding the lock across the write to w would break it - a
	// LAN client that opens the page and stops reading would hold the read lock
	// until its write buffer drains, and State.Update, called synchronously from
	// the sensor cycle, would block behind it. Go's RWMutex queues later readers
	// behind a waiting writer, so even the page that would reveal the stall goes
	// dark. The neighbour table is attacker-inflatable via spoofed ARP, so the
	// body is not small. Render, unlock, then write.
	render := func(w http.ResponseWriter, tmpl string, build func() any) {
		s.mu.RLock()
		var buf bytes.Buffer
		err := tpl.ExecuteTemplate(&buf, tmpl, build())
		s.mu.RUnlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// A dashboard about interception must not itself weaken the browser.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(buf.Bytes()) //nolint:errcheck // client gone; nothing to do
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		render(w, "home.html", func() any {
			state, sentence := s.overall()
			uptime := ""
			if !s.since.IsZero() {
				uptime = round(time.Since(s.since))
			}
			return homeData{
				State: state, Sentence: sentence, Network: s.network, Trust: s.trust,
				LastCheck: s.lastCheck, Areas: s.orderedAreas(), Alerts: toAlertViews(actionable(s.alerts)),
				Held: len(s.held), Devices: len(s.devices),
				Tier: s.tier, Witness: s.witness, Uptime: uptime,
				DeviceList: s.devices, Events: recentEvents(s.events),
			}
		})
	})

	mux.HandleFunc("/devices", func(w http.ResponseWriter, r *http.Request) {
		render(w, "devices.html", func() any {
			return devicesData{Network: s.network, Devices: s.devices}
		})
	})

	// A machine-readable mirror, for anyone who wants to build on it.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		state, _ := s.overall()
		line := fmt.Sprintf("state %s\nnetwork %s\nalerts %d\nlast_check %s\n",
			state, s.network, len(s.alerts), s.lastCheck.Format(time.RFC3339))
		s.mu.RUnlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, line) //nolint:errcheck // client gone; nothing to do
	})

	return mux
}

type homeData struct {
	State      string
	Sentence   string
	Network    string
	Trust      string
	LastCheck  time.Time
	Areas      []Area
	Alerts     []alertView
	Held       int
	Devices    int
	Tier       string
	Witness    WitnessCard
	Uptime     string
	DeviceList []Device
	Events     []Event
}

type devicesData struct {
	Network string
	Devices []Device
}

type alertView struct {
	Target   string
	Band     string
	Score    int
	Findings []findingView
}

type findingView struct {
	Band     string
	Score    int
	Title    string
	Meaning  string
	Action   string
	Evidence map[string]string
}

// actionable keeps only the alerts a person should see on the home page: Low
// band and above. Info-band findings - a routine leaf rotation, a check that
// could not run this pass - are real records but not things to act on, and
// listing them under "needs your attention" is a false alarm by another name.
func actionable(alerts []verdict.Alert) []verdict.Alert {
	var out []verdict.Alert
	for _, a := range alerts {
		if a.Band >= verdict.Low {
			out = append(out, a)
		}
	}
	return out
}

func toAlertViews(alerts []verdict.Alert) []alertView {
	var out []alertView
	for _, a := range alerts {
		av := alertView{Target: a.Target, Band: a.Band.String(), Score: a.Score}
		for _, f := range a.Findings {
			av.Findings = append(av.Findings, findingView{
				Band:     a.Band.String(),
				Score:    a.Score,
				Title:    f.Title,
				Meaning:  f.Evidence["why"],
				Action:   f.Evidence["what_to_do"],
				Evidence: f.Evidence,
			})
		}
		out = append(out, av)
	}
	return out
}

// areaOrder is the fixed left-to-right order of the six cards, so the page does
// not reshuffle between loads.
var areaOrder = []string{"router", "wifi", "dns", "tls", "devices", "outside"}

func (s *State) orderedAreas() []Area {
	out := make([]Area, 0, len(areaOrder))
	for _, k := range areaOrder {
		if a, ok := s.areas[k]; ok {
			out = append(out, a)
		}
	}
	// Anything unexpected still shows, after the known ones.
	var extra []string
	for k := range s.areas {
		if !contains(areaOrder, k) {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		out = append(out, s.areas[k])
	}
	return out
}

// areaIcon is a text glyph, not an image: the page loads nothing external, and
// an emoji costs no request.
func areaIcon(key string) string {
	switch key {
	case "router":
		return "🛜" // hut/router-ish
	case "wifi":
		return "📶"
	case "dns":
		return "🔍"
	case "tls":
		return "🔒"
	case "devices":
		return "🖥"
	case "outside":
		return "🌍"
	}
	return "•"
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func round(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h %d min", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%d days", int(d.Hours())/24)
	}
}

// favicon returns a self-contained, state-coloured tab icon as a data URI: a
// dark rounded tile with a ring and a dot in the state colour, so the browser
// tab itself flips from green to red the moment something needs attention -
// visible even when the page is in a background tab. It is embedded, never
// fetched, like everything else the dashboard serves.
func favicon(state string) template.URL {
	color := map[string]string{
		"ok":        "#2ea043",
		"attention": "#f85149",
		"learning":  "#58a6ff",
	}[state]
	if color == "" {
		color = "#6e7681"
	}
	svg := `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>` +
		`<rect width='32' height='32' rx='7' fill='#0f1115'/>` +
		`<circle cx='16' cy='16' r='8' fill='none' stroke='` + color + `' stroke-width='2.5'/>` +
		`<circle cx='16' cy='16' r='3' fill='` + color + `'/></svg>`
	return template.URL("data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg)))
}

// recentEvents returns the activity log newest-first, capped so the panel stays
// a glance rather than a scroll.
func recentEvents(evs []Event) []Event {
	const max = 12
	out := make([]Event, 0, len(evs))
	for i := len(evs) - 1; i >= 0 && len(out) < max; i-- {
		out = append(out, evs[i])
	}
	return out
}
