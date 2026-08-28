package main

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/sizzlorox/mitmwatch/internal/capture"
	"github.com/sizzlorox/mitmwatch/internal/frame"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

// frameBuffer is how far behind one capture-fed probe may fall before it starts
// losing frames. Generous on purpose: the cost is memory measured in kilobytes,
// and the cost of the alternative is missed evidence.
const frameBuffer = 2048

// pass runs each probe once and returns the findings, updating the baseline
// where it is safe to do so.
//
// Probes run concurrently. That is not for speed on its own: capture-fed probes
// each listen for the whole window, so running them one after another would
// make a pass take the window times the number of such probes, and every probe
// would be watching a different slice of time. Running together means they all
// describe the same instant, which is what makes their findings comparable.
func (e *env) pass(ctx context.Context, probes []probe.Probe) ([]probe.Finding, []error) {
	cc := e.compareCtx()

	var (
		mu       sync.Mutex
		findings []probe.Finding
		errs     []error
		adopted  = map[string]probe.Snapshot{}
		observed = map[string]probe.Snapshot{}
		errored  = map[string]bool{}
	)
	addErr := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		errs = append(errs, err)
	}

	// Sampling works against ARP poisoning specifically because the attack is
	// repetitive: a spoofer has to keep re-announcing, roughly once a second in
	// every common tool, or the real router's replies win the race back. A few
	// seconds of listening per pass is therefore enough to catch an active one.
	// `mitmwatch sensor` widens the window for anything that is not repetitive.
	src, err := capture.Open(e.cfg.Sensor.Interfaces)
	if err != nil {
		addErr(fmt.Errorf("capture: %w", err))
	}
	if src != nil {
		defer src.Close()
		e.tier = tierLabel(src.Tier())
	}

	// One socket, several readers. Each capture-fed probe gets its own buffered
	// stream so that a slow one loses only its own frames.
	streams := map[string]<-chan frame.Frame{}
	var fan *capture.Fanout
	if src != nil && src.Tier() < capture.Tier3Polling {
		fan = capture.NewFanout(src.Frames())
		for _, p := range probes {
			if probe.WantsFrames(p) {
				streams[p.Name()] = fan.Subscribe(p.Name(), frameBuffer)
			}
		}
	}

	fanCtx, stopFan := context.WithCancel(ctx)
	defer stopFan()
	if fan != nil {
		go fan.Run(fanCtx)
	}

	// Read every baseline before starting: the profile map is written below
	// from several goroutines, and reading it concurrently would be a race.
	baselines := make(map[string]probe.Snapshot, len(probes))
	for _, p := range probes {
		baselines[p.Name()] = e.profile.Snapshots[p.Name()]
	}

	var wg sync.WaitGroup
	for _, p := range probes {
		wg.Add(1)
		go func(p probe.Probe) {
			defer wg.Done()

			base := baselines[p.Name()]
			snap, err := p.Observe(ctx, probe.Inputs{
				Frames:        streams[p.Name()],
				CaptureWindow: e.cfg.CaptureWindow(),
				Baseline:      base,
				Network:       e.net,
				Config:        e.cfg,
			})
			if err != nil {
				addErr(fmt.Errorf("%s: %w", p.Name(), err))
				mu.Lock()
				errored[p.Name()] = true
				mu.Unlock()
				return
			}
			// A degraded snapshot is also "could not fully look": the sensor's
			// merge must keep the probe's previous findings rather than treat
			// this cycle as authoritative.
			if snap.Degraded {
				mu.Lock()
				errored[p.Name()] = true
				mu.Unlock()
			}
			fs := p.Compare(base, snap, cc)

			mu.Lock()
			defer mu.Unlock()
			findings = append(findings, fs...)
			// What was actually seen this pass, adopted or not. The baseline
			// deliberately refuses a snapshot that reports an unabsorbed
			// change, so anything reading Profile.Snapshots is reading the
			// world as it was *before* an attack started - correct for
			// comparison, wrong for "what is on the network right now".
			observed[p.Name()] = snap
			if snap.Degraded {
				errs = append(errs, fmt.Errorf("%s: incomplete observation, baseline left untouched: %s",
					p.Name(), snap.Err))
			}
			if adoptable(snap, fs, cc) {
				adopted[p.Name()] = snap
			}
		}(p)
	}
	wg.Wait()
	stopFan()

	for name, snap := range adopted {
		e.profile.Snapshots[name] = snap
	}

	// Frames the sensor never saw are frames it cannot report on, and a source
	// that died mid-pass looks exactly like a quiet network.
	if src != nil {
		if err := src.Err(); err != nil {
			errs = append(errs, fmt.Errorf("capture on %s failed mid-pass: %w", src.Iface(), err))
			// A source that died mid-pass fed its subscribers a closed channel,
			// and a capture-fed probe reads that as "the window ended" - it
			// returns a snapshot marked Captured with nothing in it, which is
			// indistinguishable from a quiet network. Mark those probes as
			// unable to observe, so the sensor keeps their previous findings
			// instead of reporting the condition as resolved.
			//
			// Only for a dead source. Dropped frames mean an incomplete
			// account, already reported below, and treating that as blindness
			// would pin every finding forever on a busy segment.
			for _, p := range probes {
				if probe.WantsFrames(p) {
					errored[p.Name()] = true
				}
			}
		}
		if st := src.Stats(); st.Dropped > 0 {
			errs = append(errs, fmt.Errorf("capture on %s dropped %d frame(s) at the kernel: the "+
				"sensor is not keeping up and may have missed evidence", src.Iface(), st.Dropped))
		}
	}
	if fan != nil {
		for name, n := range fan.Dropped() {
			errs = append(errs, fmt.Errorf("%s missed %d frame(s): its findings this pass are a "+
				"floor, not a full account", name, n))
		}
	}

	// The sensor's cross-cycle merge needs to know which probes could not fully
	// observe this pass, so it keeps their previous findings rather than
	// treating an errored cycle as "all clear".
	e.erroredThisPass = errored
	e.observedThisPass = observed

	// Concurrency makes the order nondeterministic, and unstable output is
	// unreadable in a diff and untestable in a soak.
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Probe != findings[j].Probe {
			return findings[i].Probe < findings[j].Probe
		}
		if findings[i].Target != findings[j].Target {
			return findings[i].Target < findings[j].Target
		}
		return findings[i].Vector < findings[j].Vector
	})
	sort.SliceStable(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	return findings, errs
}

// tierLabel is the plain-language name for the capture tier, for the dashboard
// facts strip: what the sensor is actually watching, in words a household reads.
func tierLabel(t capture.Tier) string {
	switch t {
	case capture.Tier1Pcap, capture.Tier2Raw:
		return "the wire"
	case capture.Tier3Polling:
		return "device tables"
	}
	return ""
}
