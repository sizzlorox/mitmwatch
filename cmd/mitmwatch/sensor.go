package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/core/alert"
	"github.com/sizzlorox/mitmwatch/internal/core/baseline"
	"github.com/sizzlorox/mitmwatch/internal/core/verdict"
	"github.com/sizzlorox/mitmwatch/internal/probe"
	"github.com/sizzlorox/mitmwatch/internal/web"
	"github.com/sizzlorox/mitmwatch/internal/witness"
)

// cmdSensor runs mitmwatch continuously.
//
// The daemon deliberately adds no new probe interface. It calls Observe and
// Compare exactly as `check` does, on each probe's own Interval, with a longer
// capture window - and probe.Inputs.Baseline already carries the accumulation
// that a long-running observation needs. A parallel streaming interface would
// mean two code paths to keep correct, and the second one would be the one
// nobody tests. Anyone adding a probe should write it for `check`; running
// under the daemon then costs nothing.
//
// What the daemon buys is time on the wire. A one-shot check samples a few
// seconds every fifteen minutes, which is enough for ARP poisoning because that
// repeats about once a second, and not enough for anything that happens once -
// a single rogue DHCP offer, one router advertisement, one poisoned name
// lookup. Here the window is long enough that "between windows" stops being a
// meaningful gap.
func cmdSensor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("sensor", flag.ExitOnError)
	cfgPath, profileDir := commonFlags(fs)
	once := fs.Bool("once", false, "run a single cycle and exit; for testing the configuration")
	interval := fs.Duration("interval", 0, "override the shortest probe interval")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}

	e, err := setup(ctx, *cfgPath, *profileDir)
	if err != nil {
		return err
	}
	// Fail before going resident rather than after: a daemon that starts and
	// then cannot deliver is worse than one that refuses to start.
	if _, err := alert.Sinks(e.cfg, io.Discard); err != nil {
		return err
	}

	probes := probe.All()
	if len(probes) == 0 {
		return errors.New("no probes registered")
	}

	if e.cfg.Sensor.Dashboard != "" {
		e.dash = web.NewState()
		if _, err := serveDashboard(ctx, e.cfg.Sensor.Dashboard, e.dash); err != nil {
			return fmt.Errorf("dashboard: %w", err)
		}
	}

	// The witness link, when configured. It runs in the background and the
	// sensor reads its View() each cycle through compareCtx - no coupling into
	// this loop, so a witness that is down or absent changes nothing here.
	if e.cfg.Witness.Sync && e.cfg.Witness.Addr != "" && e.cfg.Witness.Pin != "" {
		id, err := witness.LoadOrCreateIdentity(witnessKeyDir(e.cfg), "mitmwatch-sensor")
		if err != nil {
			return fmt.Errorf("witness identity: %w", err)
		}
		e.link = witness.NewLink(e.cfg, id, e.sensorObserve)
		go e.link.Run(ctx)
	}

	tick := *interval
	if tick <= 0 {
		tick = shortestInterval(probes)
	}

	// What the daemon is actually for. `check` samples a few seconds and
	// returns; the resident sensor should be listening almost all the time, or
	// "between windows" is where every one-shot event happens.
	e.captureWindow = sensorWindow(tick, e.cfg.CaptureWindow())

	fmt.Printf("mitmwatch sensor %s\n", version)
	fmt.Printf("  network   %s (profile %s, trust %s)\n", e.net.Label(), e.profile.Key, e.profile.Trust)
	fmt.Printf("  probes    %d, cycle every %s\n", len(probes), tick)
	fmt.Printf("  listening %s of every %s\n", e.captureWindow, tick)
	fmt.Printf("  sinks     %s\n", sinkNames(e))
	if e.cfg.Sensor.Dashboard != "" {
		fmt.Printf("  dashboard http://%s\n", dashboardHost(e.cfg.Sensor.Dashboard))
	}
	if e.link != nil {
		fmt.Printf("  witness   %s (outside comparison enabled)\n", e.cfg.Witness.Addr)
	}
	if e.profile.Learning() {
		fmt.Printf("  learning  %s left; only critical findings surface until then\n",
			e.profile.LearningLeft().Round(time.Second))
	}
	fmt.Println()

	e.since = time.Now()
	// Pick the activity log back up where the last run left it. Without this a
	// restart - which happens on every upgrade, and on any crash under
	// Restart=always - blanks the record to a single line, and a household
	// looking the morning after an incident sees a network on which nothing has
	// ever happened.
	evs, err := e.store.LoadEvents(e.profile.Key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "activity log:", err)
	}
	e.events = evs
	e.eventsTotal = len(evs)
	e.addEvent(baseline.Event{When: e.since, Kind: "system", Text: "Sensor started"})
	if err := e.store.SaveEvents(e.profile.Key, e.events); err != nil {
		fmt.Fprintln(os.Stderr, "activity log:", err)
	}
	e.eventsDirty = false

	// due tracks when each probe should next run, so a probe asking for 15
	// minutes is not run every two just because another one is.
	due := make(map[string]time.Time, len(probes))
	now := time.Now()
	for _, p := range probes {
		due[p.Name()] = now
	}

	for {
		batch := make([]probe.Probe, 0, len(probes))
		now = time.Now()
		for _, p := range probes {
			if !now.Before(due[p.Name()]) {
				batch = append(batch, p)
				iv := p.Interval()
				if iv <= 0 {
					iv = tick
				}
				due[p.Name()] = now.Add(iv)
			}
		}

		if len(batch) > 0 {
			if err := e.cycle(ctx, batch); err != nil {
				// A failed cycle must not kill the sensor. A sensor that exits
				// on the first transient error is a sensor that is not running
				// on the night it was needed.
				fmt.Fprintln(os.Stderr, "cycle:", err)
			}
		}
		if *once {
			return nil
		}

		// Sleep what is LEFT of the tick, not a whole one. Sleeping a full tick
		// after the cycle made the real period pass+tick, which was invisible
		// while a pass took five seconds and would throw away most of the
		// benefit now that a pass takes most of the interval.
		if wait := tick - time.Since(now); wait > 0 {
			select {
			case <-ctx.Done():
				fmt.Println("\nstopping")
				return e.store.Save(e.profile)
			case <-time.After(wait):
			}
		} else if ctx.Err() != nil {
			fmt.Println("\nstopping")
			return e.store.Save(e.profile)
		}
	}
}

// sensorWindow is how long the resident sensor listens each cycle.
//
// The one-shot `check` samples for a few seconds because it has to return to a
// person. A daemon has no such excuse, and the difference is the whole point of
// running one: ARP poisoning repeats about once a second so a short sample
// catches it, but a single rogue DHCP offer, one router advertisement or one
// poisoned name lookup happens once - and five seconds in every two minutes
// misses those about ninety-six times out of a hundred.
//
// So listen for nearly the whole cycle, leaving headroom for the probes that do
// not read the wire - the TLS handshakes and DoH lookups - to finish inside the
// same pass, and for the profile write at the end of it. Never shorter than the
// configured one-shot window, and capped so an unusually long interval cannot
// hold one capture socket open for an hour.
func sensorWindow(tick, floor time.Duration) time.Duration {
	const (
		headroom = 30 * time.Second
		ceiling  = 5 * time.Minute
	)
	w := tick - headroom
	if w < floor {
		w = floor
	}
	if w > ceiling {
		w = ceiling
	}
	return w
}

// mergeFindings maintains the union of every probe's most recent findings.
//
// It replaces the entries for the probes that ran this cycle and returns the
// union with everything still current from earlier cycles. A probe that ran and
// errored keeps its previous findings rather than clearing them - an error is
// "I could not look", not "all clear", the same distinction the degraded-
// snapshot rule makes. An entry is dropped once it is older than twice that
// probe's interval, so a condition that genuinely cleared does not linger.
func (e *env) mergeFindings(ran []probe.Probe, fresh []probe.Finding) []probe.Finding {
	if e.recent == nil {
		e.recent = map[string]recentFindings{}
	}
	now := time.Now()

	// Group this cycle's findings by the probe that produced them.
	byProbe := map[string][]probe.Finding{}
	for _, f := range fresh {
		byProbe[f.Probe] = append(byProbe[f.Probe], f)
	}
	// Replace the stored entry for every probe that ran AND returned a snapshot.
	// erroredThisPass is how we tell "ran clean, found nothing" (replace with
	// empty) from "ran and errored" (keep the previous view).
	for _, p := range ran {
		if e.erroredThisPass[p.Name()] {
			continue
		}
		iv := p.Interval()
		if iv <= 0 {
			iv = 2 * time.Minute
		}
		e.recent[p.Name()] = recentFindings{at: now, ttl: 2 * iv, findings: byProbe[p.Name()]}
	}

	// Union, dropping anything stale.
	var out []probe.Finding
	for name, r := range e.recent {
		if now.Sub(r.at) > r.ttl {
			delete(e.recent, name)
			continue
		}
		out = append(out, r.findings...)
	}
	return out
}

// sensorObserve answers a witness tick with the sensor's own tls/dns view, for
// the witness's history and audit. It runs the same probes the sensor already
// runs; nothing here feeds back into the sensor's own detection.
func (e *env) sensorObserve(ctx context.Context, targets []string) map[string]probe.Snapshot {
	out := map[string]probe.Snapshot{}
	for _, name := range []string{"tls", "dns"} {
		if p, ok := probe.Get(name); ok {
			if s, err := p.Observe(ctx, probe.Inputs{Config: e.cfg}); err == nil {
				out[name] = s
			}
		}
	}
	return out
}

// cycle is one pass: observe, compare, alert, persist.
func (e *env) cycle(ctx context.Context, probes []probe.Probe) error {
	// Re-read the network each cycle. A sensor that moves - a laptop, or a Pi
	// whose gateway changed - must switch profiles rather than compare the new
	// network against the old one's baseline.
	if err := e.refresh(ctx); err != nil {
		return err
	}

	fresh, probeErrs := e.pass(ctx, probes)

	// Evaluate the whole world, not just the probes that were due this cycle.
	//
	// Probes run on different intervals - tls/dns every 5m, clock every 15m,
	// the L2 probes every 2m - so most cycles carry only a subset. Judging that
	// subset as if it were everything broke three things at once: a persistent
	// High from a probe absent this cycle had its cooldown forgotten and
	// re-pushed every couple of minutes; its dashboard card reverted to green;
	// and two probes that score the same target never summed, so a pair that is
	// Critical under `check` surfaced as two lesser alerts. The union of each
	// probe's most recent findings is the honest picture, and it makes the
	// sensor agree with `check`.
	findings := e.mergeFindings(probes, fresh)
	res := verdict.Evaluate(findings, e.compareCtx())

	for _, err := range probeErrs {
		fmt.Fprintln(os.Stderr, "probe:", err)
	}
	for _, err := range e.deliver(ctx, res, findings, os.Stdout) {
		fmt.Fprintln(os.Stderr, "alert:", err)
	}

	// The device history and the activity log are recorded whether or not the
	// dashboard is running. They are the record; the page is one way of reading
	// it, and a headless sensor that remembered nothing would have nothing to
	// show the moment someone turned the page on.
	e.recordDeviceHistory(ctx, time.Now())
	e.recordEvents(res)
	if e.eventsDirty {
		if err := e.store.SaveEvents(e.profile.Key, e.events); err != nil {
			fmt.Fprintln(os.Stderr, "activity log:", err)
		}
		e.eventsDirty = false
	}

	if e.dash != nil {
		wv := e.witnessView()
		var checks []web.CheckTiming
		var auditFindings []web.AuditFinding
		if e.cfg.Sensor.Audit {
			checks = dashboardChecks(e.checks, wv)
			auditFindings = e.dashboardFindings(res.Alerts, res.Held)
		}
		e.dash.Update(web.Update{
			Network:  e.net.Label(),
			Profile:  e.profile.Key,
			Trust:    e.profile.Trust,
			Learning: e.profile.LearningLeft(),
			When:     time.Now(),
			Alerts:   res.Alerts,
			Held:     res.Held,
			Areas:    buildAreas(res.Alerts, res.Held, e.profile.Learning()),
			Devices:  e.dashboardDevices(),
			Tier:     e.tier,
			Witness: web.WitnessCard{
				Configured: wv.Configured, Connected: wv.Available,
				Addr: e.cfg.Witness.Addr, LastSeen: wv.ObservedAt,
			},
			Since:        e.since,
			Events:       webEvents(e.events),
			EventsTotal:  e.eventsTotal,
			DevicesAt:    e.lastCycle,
			AuditEnabled: e.cfg.Sensor.Audit,
			Checks:       checks,
			Findings:     auditFindings,
		})
	}
	return e.store.Save(e.profile)
}

// refresh re-identifies the network and switches profile if it changed.
func (e *env) refresh(ctx context.Context) error {
	n, netErr := identifyNetwork(ctx)
	if netErr != nil {
		// Keep going with the previous identity: a transient failure to read a
		// routing table should not stop the probes that do not need it.
		return nil
	}
	if n.Key() == e.profile.Key {
		e.net = n
		return nil
	}

	// Different network. Persist what was learned about the old one before
	// moving, or the last cycle's observations are lost.
	if err := e.store.Save(e.profile); err != nil {
		return err
	}
	// The activity log and the device history are per network, and both are
	// keyed by the profile. Carrying the in-memory log across would write what
	// happened at the cafe into the file for home, and then show it there.
	if err := e.store.SaveEvents(e.profile.Key, e.events); err != nil {
		fmt.Fprintln(os.Stderr, "activity log:", err)
	}
	window := time.Duration(e.cfg.Learning.WindowMin) * time.Minute
	if window <= 0 {
		window = 10 * time.Minute
	}
	prof, fresh, err := e.store.Load(n, window)
	if err != nil {
		return err
	}
	e.net, e.profile, e.fresh = n, prof, fresh

	evs, err := e.store.LoadEvents(prof.Key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "activity log:", err)
	}
	e.events, e.eventsTotal, e.eventsDirty = evs, len(evs), false
	// Standing alerts belong to the network they were found on. Diffing this
	// network's findings against the last one's would announce every alert as
	// resolved on arrival, and raise them again on the way back.
	e.alerted, e.heldSeen = nil, nil
	e.lastCycle = time.Time{}
	e.addEvent(baseline.Event{When: time.Now(), Kind: "system",
		Text: "Network changed - now watching " + n.Label()})
	fmt.Printf("network changed: now %s (profile %s, trust %s)\n", n.Label(), prof.Key, prof.Trust)
	return nil
}

func shortestInterval(probes []probe.Probe) time.Duration {
	shortest := time.Duration(0)
	for _, p := range probes {
		iv := p.Interval()
		if iv <= 0 {
			continue
		}
		if shortest == 0 || iv < shortest {
			shortest = iv
		}
	}
	if shortest <= 0 {
		return 2 * time.Minute
	}
	return shortest
}

func sinkNames(e *env) string {
	sinks, err := alert.Sinks(e.cfg, io.Discard)
	if err != nil {
		return "(invalid)"
	}
	names := make([]string, 0, len(sinks))
	for _, s := range sinks {
		names = append(names, s.Name())
	}
	sort.Strings(names)
	return joinComma(names)
}

func joinComma(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}

// addEvent appends to the activity log and marks it for saving. The in-memory
// list is bounded the same way the stored one is.
func (e *env) addEvent(ev baseline.Event) {
	e.events = append(e.events, ev)
	if len(e.events) > baseline.MaxEvents {
		e.events = e.events[len(e.events)-baseline.MaxEvents:]
	}
	e.eventsTotal++
	e.eventsDirty = true
}

// webEvents converts the stored log into the dashboard's view of it.
func webEvents(evs []baseline.Event) []web.Event {
	out := make([]web.Event, 0, len(evs))
	for _, ev := range evs {
		out = append(out, web.Event{
			When: ev.When, Kind: ev.Kind, Text: ev.Text,
			Target: ev.Target, Device: ev.Device, Band: ev.Band,
			Vectors: ev.Vectors, Hashes: ev.Hashes, Evidence: ev.Evidence,
		})
	}
	return out
}

// raised is what was known about an alert at the moment it was raised.
//
// It is kept because the clear path runs when the findings are already gone
// from the result: by then all that is left of an alert is the target string it
// was filed under. Without this, an alert that resolves leaves behind a line
// reading "Resolved: fe80::c0a8:1ff:fe24:9b31" - which names neither the
// device nor what was seen, and is the whole reason this exists.
type raised struct {
	Label    string
	Device   string
	Band     string
	Vectors  []string
	Hashes   []string
	Probes   []string
	Evidence map[string]string
}

// recordEvents turns this cycle's result into activity-log entries by diffing
// against the last cycle: an actionable target that is newly present is an
// alert raised, one that has gone is an alert cleared. It also notes the
// one-off transitions a watcher cares about - the learning window closing, and
// the outside witness connecting or dropping.
//
// The log is the record. It is written to disk beside the profile, kept across
// restarts, and carries the evidence with each entry, because the question
// someone actually asks the next morning is not "did something happen" but
// "what was it, and which machine".
func (e *env) recordEvents(res verdict.Result) {
	if e.alerted == nil {
		e.alerted = map[string]raised{}
	}
	now := time.Now()

	// What is actionable, using the same bar the six cards use: Low and above,
	// plus the Info-band vectors that mean "this check could not run". A card
	// greying out to say a check has stopped, while the log beside it stays
	// silent, is the page disagreeing with itself.
	cur := map[string]raised{}
	for _, a := range res.Alerts {
		if !actionableAlert(a) {
			continue
		}
		cur[a.Target] = e.describe(a)
	}

	for t, r := range cur {
		if _, was := e.alerted[t]; was {
			continue
		}
		e.addEvent(baseline.Event{
			When: now, Kind: "alert", Text: r.Label,
			Target: t, Device: r.Device, Band: r.Band,
			Vectors: r.Vectors, Hashes: r.Hashes, Evidence: r.Evidence,
		})
	}

	for t, r := range e.alerted {
		if _, still := cur[t]; still {
			continue
		}
		// A finding that vanished because its probe went blind has not been
		// resolved. Capture dying mid-pass closes the frame channel, and a
		// capture-fed probe reads that as an empty window - which looks exactly
		// like a quiet network. Saying "resolved" there is the failure this
		// project names as its most repeated: silence that looks like success.
		kind, text := "clear", r.Label+" - resolved"
		if e.blindFor(r.Probes) {
			kind, text = "stale", "No longer being checked: "+r.Label
		}
		e.addEvent(baseline.Event{
			When: now, Kind: kind, Text: text,
			Target: t, Device: r.Device, Band: r.Band,
			Vectors: r.Vectors, Hashes: r.Hashes, Evidence: r.Evidence,
		})
	}
	e.alerted = cur

	// Findings held back by the learning window or the accept list. They are
	// true and merely suppressed, and the held list exists precisely so that
	// suppression is visible - a detector that hides its own suppressions
	// cannot be trusted about anything else.
	if e.heldSeen == nil {
		e.heldSeen = map[string]bool{}
	}
	held := map[string]bool{}
	for _, a := range res.Held {
		if !actionableAlert(a) {
			continue
		}
		held[a.Target] = true
		if e.heldSeen[a.Target] {
			continue
		}
		r := e.describe(a)
		why := a.Suppressed
		if why == "" {
			why = "held back"
		}
		e.addEvent(baseline.Event{
			When: now, Kind: "held", Text: r.Label + " - " + why,
			Target: a.Target, Device: r.Device, Band: r.Band,
			Vectors: r.Vectors, Hashes: r.Hashes, Evidence: r.Evidence,
		})
	}
	e.heldSeen = held

	// Learning finished - only once, and only if we actually watched the window
	// close (an already-learned profile that just restarted did not "finish"
	// now, and must not claim to).
	if e.profile.Learning() {
		e.sawLearning = true
	} else if e.sawLearning && !e.learnedOnce {
		e.addEvent(baseline.Event{When: now, Kind: "system",
			Text: "Finished learning this network - now watching for changes"})
		e.learnedOnce = true
	}

	// Witness link coming or going.
	if e.link != nil {
		up := e.witnessView().Available
		if up != e.witnessUp {
			text := "Outside witness link lost"
			if up {
				text = "Outside witness connected"
			}
			e.addEvent(baseline.Event{When: now, Kind: "system", Text: text})
			e.witnessUp = up
		}
	}
}

// actionableAlert is the shared bar for "this is activity": Low band and above,
// or an Info-band finding that means a check could not run. A routine Info
// finding - a certificate rotating - is not something that changed.
func actionableAlert(a verdict.Alert) bool {
	if a.Band >= verdict.Low {
		return true
	}
	for _, f := range a.Findings {
		if couldNotCheck[f.Vector] {
			return true
		}
	}
	return false
}

// describe flattens an alert into what the log needs to still make sense once
// the alert itself is gone.
func (e *env) describe(a verdict.Alert) raised {
	r := raised{Band: a.Band.String(), Evidence: map[string]string{}}
	seenProbe := map[string]bool{}
	for _, f := range a.Findings {
		if r.Label == "" && f.Title != "" {
			r.Label = f.Title
		}
		r.Vectors = append(r.Vectors, f.Vector)
		r.Hashes = append(r.Hashes, f.Hash())
		if !seenProbe[f.Probe] {
			seenProbe[f.Probe] = true
			r.Probes = append(r.Probes, f.Probe)
		}
		// Copied, never aliased: the finding's map outlives this call inside
		// e.recent, and a later cycle rewriting it would silently rewrite
		// history.
		for k, v := range f.Evidence {
			if _, dup := r.Evidence[k]; !dup {
				r.Evidence[k] = v
			}
		}
	}
	if r.Label == "" {
		r.Label = "Something was found on " + a.Target
	}
	// Named after the evidence is gathered, so the hardware a probe reported can
	// stand in when the target itself matches no address in the history - which
	// is every link-local target, since the neighbour table is IPv4 only.
	r.Device = e.deviceLabel(a.Target, r.Evidence["hardware"])
	if len(r.Evidence) == 0 {
		r.Evidence = nil
	}
	return r
}

// blindFor reports whether any probe behind an alert failed to observe this
// pass, which is the difference between "it stopped" and "we stopped looking".
func (e *env) blindFor(probes []string) bool {
	for _, p := range probes {
		if e.erroredThisPass[p] {
			return true
		}
	}
	return false
}
