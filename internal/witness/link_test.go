package witness

import (
	"context"
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

// linkPair wires a real Server and Link over an in-process pinned-mTLS listener
// and returns the running link plus a way to control what the witness observes.
func linkPair(t *testing.T, witObs Observer, sensorCfg *config.Config) (*Link, func()) {
	t.Helper()
	sensorID := newIdentity(t, "mitmwatch-sensor")
	witID := newIdentity(t, "mitmwatch-witness")

	witCfg := config.Defaults()
	witCfg.Witness.Listen = "127.0.0.1:0"
	witCfg.Witness.AllowPins = []string{sensorID.Pin}
	witCfg.Witness.TickInterval = "200ms"
	witCfg.TLS.Pin = sensorCfg.TLS.Pin
	witCfg.DNS.Anchors = sensorCfg.DNS.Anchors

	// Bind explicitly so we know the port.
	hist := LoadHistory(t.TempDir() + "/h.json")
	srv := NewServer(witID, witCfg, witObs, hist, func(string, string, time.Time) {}, nil)

	// Serve needs a listener; use a real one and hand its addr to the sensor.
	ln := mustListen(t, witID, witCfg)
	ctx, cancel := context.WithCancel(context.Background())
	go srv.serveOn(ctx, ln)

	sensorCfg.Witness.Sync = true
	sensorCfg.Witness.Addr = ln.Addr().String()
	sensorCfg.Witness.Pin = witID.Pin
	sensorCfg.Witness.ConfirmTicks = 2
	sensorCfg.Witness.Freshness = "10s"
	sensorCfg.Witness.BeatSec = 1

	link := NewLink(sensorCfg, sensorID, nil)
	go link.Run(ctx)
	return link, cancel
}

// A steady witness view becomes available and its hosts become stable after
// confirm_ticks.
func TestLinkBecomesAvailableAndStable(t *testing.T) {
	obs := func(_ context.Context, targets []string) (map[string]probe.Snapshot, map[string]WitnessTLS) {
		snap := tlsSnapFor(t, targets, "Sectigo", "key1", "CN=Root", true, 3, "leafA")
		facts := map[string]WitnessTLS{}
		for _, h := range targets {
			facts[h] = WitnessTLS{IssuerO: "Sectigo", IssuerSPKI: "key1", RootSubject: "CN=Root", HasSCT: true}
		}
		return map[string]probe.Snapshot{"tls": snap}, facts
	}
	cfg := config.Defaults()
	cfg.TLS.Pin = []string{"github.com"}
	cfg.DNS.Anchors = nil

	link, stop := linkPair(t, obs, cfg)
	defer stop()

	// Wait for the view to become available and stable.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		v := link.View()
		if v.Available && v.StableHost("github.com") {
			if _, ok := v.Snapshot("tls"); !ok {
				t.Fatal("view available but tls snapshot missing")
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("witness view never became available+stable; last: %+v", link.View())
}

// A witness whose view keeps changing never marks a host stable, so a flapping
// witness cannot drive a finding.
func TestFlappingWitnessNeverStable(t *testing.T) {
	i := 0
	obs := func(_ context.Context, targets []string) (map[string]probe.Snapshot, map[string]WitnessTLS) {
		i++
		leaf := "leaf" + string(rune('A'+i%5)) // changes every tick
		return map[string]probe.Snapshot{"tls": tlsSnapFor(t, targets, "Sectigo", "key1", "CN=Root", true, 3, leaf)},
			nil
	}
	cfg := config.Defaults()
	cfg.TLS.Pin = []string{"github.com"}
	cfg.DNS.Anchors = nil

	link, stop := linkPair(t, obs, cfg)
	defer stop()

	time.Sleep(1500 * time.Millisecond) // several ticks
	if link.View().StableHost("github.com") {
		t.Fatal("a flapping witness marked a host stable")
	}
	if !link.View().Available {
		t.Fatal("view should still be available (fresh ticks), just not stable")
	}
}

// A stale link (no ticks past freshness) downgrades to unavailable on the
// sensor's own clock.
func TestStaleViewBecomesUnavailable(t *testing.T) {
	cfg := config.Defaults()
	cfg.TLS.Pin = []string{"github.com"}
	cfg.Witness.Sync = true
	cfg.Witness.Addr = "203.0.113.1:1"
	cfg.Witness.Pin = "sha256/" + "00"
	cfg.Witness.Freshness = "50ms"

	id := newIdentity(t, "mitmwatch-sensor")
	link := NewLink(cfg, id, nil)
	// Simulate a tick having arrived, then going stale.
	link.mu.Lock()
	link.lastRecv = time.Now().Add(-time.Second)
	link.mu.Unlock()
	link.publish(probe.NewWitnessView(true, true, false, "", time.Now(),
		map[string]probe.Snapshot{"tls": tlsSnapFor(t, []string{"github.com"}, "Sectigo", "k", "r", true, 3, "l")},
		map[string]bool{"github.com": true}))

	v := link.View()
	if v.Available {
		t.Fatal("a stale view stayed available; freshness not enforced on the sensor clock")
	}
}
