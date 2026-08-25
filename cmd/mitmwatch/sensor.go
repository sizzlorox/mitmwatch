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

	fmt.Printf("mitmwatch sensor %s\n", version)
	fmt.Printf("  network   %s (profile %s, trust %s)\n", e.net.Label(), e.profile.Key, e.profile.Trust)
	fmt.Printf("  probes    %d, cycle every %s\n", len(probes), tick)
	fmt.Printf("  listening %s per cycle\n", e.cfg.CaptureWindow())
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
	if e.dash != nil {
		e.events = append(e.events, web.Event{When: e.since, Kind: "system", Text: "Sensor started"})
	}

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

		select {
		case <-ctx.Done():
			fmt.Println("\nstopping")
			return e.store.Save(e.profile)
		case <-time.After(tick):
		}
	}
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

	if e.dash != nil {
		e.recordEvents(res)
		wv := e.witnessView()
		e.dash.Update(web.Update{
			Network:  e.net.Label(),
			Profile:  e.profile.Key,
			Trust:    e.profile.Trust,
			Learning: e.profile.LearningLeft(),
			When:     time.Now(),
			Alerts:   res.Alerts,
			Held:     res.Held,
			Areas:    buildAreas(res.Alerts, res.Held, e.profile.Learning()),
			Devices:  e.dashboardDevices(ctx),
			Tier:     e.tier,
			Witness: web.WitnessCard{
				Configured: wv.Configured, Connected: wv.Available,
				Addr: e.cfg.Witness.Addr, LastSeen: wv.ObservedAt,
			},
			Since:  e.since,
			Events: e.events,
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
	window := time.Duration(e.cfg.Learning.WindowMin) * time.Minute
	if window <= 0 {
		window = 10 * time.Minute
	}
	prof, fresh, err := e.store.Load(n, window)
	if err != nil {
		return err
	}
	e.net, e.profile, e.fresh = n, prof, fresh
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

// recordEvents turns this cycle's result into activity-log entries by diffing
// against the last cycle: an actionable target that is newly present is an
// alert raised, one that has gone is an alert cleared. It also notes the
// one-off transitions a watcher cares about - the learning window closing, and
// the outside witness connecting or dropping. The log is bounded so it stays a
// glance, and it lives only in memory: it is a convenience for the live page,
// not a record (the log sink is the record).
func (e *env) recordEvents(res verdict.Result) {
	if e.alerted == nil {
		e.alerted = map[string]bool{}
	}
	now := time.Now()
	add := func(kind, text string) {
		e.events = append(e.events, web.Event{When: now, Kind: kind, Text: text})
		if len(e.events) > 60 {
			e.events = e.events[len(e.events)-60:]
		}
	}

	// Only Low-band and above is "activity" - a routine Info finding is not
	// something changed, the same bar the home alert list uses.
	cur := map[string]string{}
	for _, a := range res.Alerts {
		if a.Band < verdict.Low {
			continue
		}
		label := a.Target
		if len(a.Findings) > 0 && a.Findings[0].Title != "" {
			label = a.Findings[0].Title
		}
		cur[a.Target] = label
	}
	for t, label := range cur {
		if !e.alerted[t] {
			add("alert", label)
		}
	}
	for t := range e.alerted {
		if _, ok := cur[t]; !ok {
			add("clear", "Resolved: "+t)
		}
	}
	e.alerted = map[string]bool{}
	for t := range cur {
		e.alerted[t] = true
	}

	// Learning finished - only once, and only if we actually watched the window
	// close (an already-learned profile that just restarted did not "finish"
	// now, and must not claim to).
	if e.profile.Learning() {
		e.sawLearning = true
	} else if e.sawLearning && !e.learnedOnce {
		add("system", "Finished learning this network - now watching for changes")
		e.learnedOnce = true
	}

	// Witness link coming or going.
	if e.link != nil {
		up := e.witnessView().Available
		if up != e.witnessUp {
			if up {
				add("system", "Outside witness connected")
			} else {
				add("system", "Outside witness link lost")
			}
			e.witnessUp = up
		}
	}
}
