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

	network     string
	profile     string
	trust       string
	learning    time.Duration
	lastCheck   time.Time
	alerts      []verdict.Alert
	held        []verdict.Alert
	areas       map[string]Area
	devices     []Device
	tier        string
	witness     WitnessCard
	since       time.Time
	events      []Event
	eventsTotal int
	devicesAt   time.Time
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

// Event is one entry in the activity log: an alert raised, cleared, held back
// or no longer being checked, a learning window finishing, the witness link
// coming or going.
//
// It carries the evidence, not only the headline. The case that matters is an
// alert that has since cleared: the card is green again, the alert card is
// gone, and the log line is the only thing left. A line that cannot say which
// device it was about, or what was actually seen, tells a person that something
// happened and nothing more - which is worse than not knowing, because now they
// know to worry.
type Event struct {
	When time.Time
	Kind string // "alert" | "clear" | "stale" | "held" | "system"
	Text string
	// Target is what it was about; Device is that target in human terms, as it
	// was known at the time.
	Target   string
	Device   string
	Band     string
	Vectors  []string
	Hashes   []string
	Evidence map[string]string
}

// Area is one of the plain-language sections: the router, the Wi-Fi, and so on.
type Area struct {
	Key   string
	Name  string
	State string // "ok" | "attention" | "learning" | "unknown"
	Line  string
}

// Device is one host this network has been seen to contain.
//
// It is drawn from the stored history, not from the live neighbour table, which
// is what lets the page show a device that is no longer connected. Present says
// whether it was there in the last completed cycle.
type Device struct {
	IP   string
	MAC  string
	Name string
	// FirstSeen is when this hardware address first appeared on this network.
	// Named for what it is: the previous field was the profile's own creation
	// time, identical on every row.
	FirstSeen time.Time
	LastSeen  time.Time
	Present   bool
	// Random marks a locally administered address. Phones rotate these, so the
	// history is of the address and not of the device, and the page says so
	// rather than claiming a life the record cannot have.
	Random bool
	Addrs  []string
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
	s.eventsTotal = u.EventsTotal
	s.devicesAt = u.DevicesAt
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
	// EventsTotal is how many entries have ever been recorded on this network,
	// which is more than Events holds once the retained window fills. A page
	// showing part of a log must be able to say so: a truncated log that looks
	// complete reads as a quiet network.
	EventsTotal int
	// DevicesAt is when the device list was last actually read. It is not the
	// same as When: the neighbour table is only read on the cycles the arp probe
	// runs and manages to observe, so a page that showed only the cycle time
	// would report devices as connected now on the strength of a reading it
	// never took.
	DevicesAt time.Time
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

// execLocked builds the render model and executes the template against it, both
// under the read lock, and releases the lock with a defer.
//
// The defer is the point. build and the template run text the wire put there -
// device names, evidence values - through code that can panic, and net/http
// recovers a handler panic per connection, so the request merely dies. A read
// lock released by a statement after the call would not be released at all, and
// State.Update, called synchronously from the sensor cycle, blocks on Lock
// forever: one page load would stop the detector. Go's RWMutex also queues
// later readers behind that waiting writer, so even the page that would show
// the stall goes dark.
func (s *State) execLocked(exec func(any) error, build func() any) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return exec(build())
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
			// A timestamp in the future is a clock disagreement between the
			// sensor and whoever is reading the page, not a device seen
			// tomorrow. This tool ships a clock probe because that drift is
			// real; "in under a minute ago" is how it used to read.
			if d := time.Since(t); d >= 0 {
				return round(d) + " ago"
			}
			return "just now"
		},
		"at":    at,
		"clock": clock,
		"sub":   func(a, b int) int { return a - b },
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
		var buf bytes.Buffer
		err := s.execLocked(func(v any) error { return tpl.ExecuteTemplate(&buf, tmpl, v) }, build)

		// Headers first, so the error branch below is covered too: a template
		// that fails must not serve a body with no policy on it.
		//
		// A dashboard about interception must not itself weaken the browser.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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
				EventsTotal: s.eventsTotal, EventsKept: len(s.events),
				EventsShown: len(recentEvents(s.events)), DevicesAt: s.devicesAt,
			}
		})
	})

	mux.HandleFunc("/devices", func(w http.ResponseWriter, r *http.Request) {
		render(w, "devices.html", func() any {
			return devicesData{Network: s.network, Devices: s.devices}
		})
	})

	// The activity log in full, with the evidence behind each entry.
	//
	// A separate page rather than an expander on the home page: the home page
	// refreshes itself every fifteen seconds, which would close anything the
	// reader had opened. This is where "what was that alert, actually" gets
	// answered, so it has to stay open long enough to read.
	mux.HandleFunc("/activity", func(w http.ResponseWriter, r *http.Request) {
		render(w, "activity.html", func() any {
			return activityData{Network: s.network, Events: reversed(s.events),
				Total: s.eventsTotal, Kept: len(s.events)}
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
	State       string
	Sentence    string
	Network     string
	Trust       string
	LastCheck   time.Time
	Areas       []Area
	Alerts      []alertView
	Held        int
	Devices     int
	Tier        string
	Witness     WitnessCard
	Uptime      string
	DeviceList  []Device
	Events      []Event
	EventsTotal int
	EventsKept  int
	EventsShown int
	DevicesAt   time.Time
}

type devicesData struct {
	Network string
	Devices []Device
}

type activityData struct {
	Network string
	Events  []Event
	Total   int
	Kept    int
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

// at is the absolute form of a timestamp, for the places where "41 min ago" is
// not enough to line an event up against something else that happened.
//
// The zone is printed because a household reads this page from a phone that may
// not be in the sensor's timezone, and the year because a device history spans
// months - "Jan 2 15:04" stops being unambiguous the moment it does.
func at(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Local().Format("2006-01-02 15:04 MST")
}

// clock is the short absolute form, for a column that already carries the
// relative age beside it.
func clock(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format("2006-01-02 15:04")
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

// homeEvents is how much of the log the home panel shows. The rest is one click
// away on /activity, and the page says how many are not shown - a log that has
// been cut off must not read as a network on which nothing else happened.
const homeEvents = 12

// recentEvents returns the activity log newest-first, capped so the panel stays
// a glance rather than a scroll.
func recentEvents(evs []Event) []Event {
	out := make([]Event, 0, homeEvents)
	for i := len(evs) - 1; i >= 0 && len(out) < homeEvents; i-- {
		out = append(out, evs[i])
	}
	return out
}

// reversed returns the whole log newest-first.
func reversed(evs []Event) []Event {
	out := make([]Event, 0, len(evs))
	for i := len(evs) - 1; i >= 0; i-- {
		out = append(out, evs[i])
	}
	return out
}
