package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/core/alert"
	"github.com/sizzlorox/mitmwatch/internal/core/verdict"
	"github.com/sizzlorox/mitmwatch/internal/probe"
	"github.com/sizzlorox/mitmwatch/internal/witness"
)

// witnessKeyDir is where a box's identity lives, config-overridable.
func witnessKeyDir(cfg *config.Config) string {
	if cfg.Witness.KeyDir != "" {
		return cfg.Witness.KeyDir
	}
	if os.Geteuid() == 0 {
		return "/var/lib/mitmwatch/witness"
	}
	d, _ := os.UserConfigDir()
	return filepath.Join(d, "mitmwatch", "witness")
}

func cmdWitness(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: mitmwatch witness serve|keygen|pair|allow|history|status")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "serve":
		return witnessServe(ctx, rest)
	case "keygen":
		return witnessKeygen(ctx, rest)
	case "pair":
		return witnessPair(ctx, rest)
	case "allow":
		return witnessAllow(ctx, rest)
	case "history":
		return witnessHistory(ctx, rest)
	case "status":
		return witnessStatus(ctx, rest)
	}
	return fmt.Errorf("unknown witness subcommand %q", sub)
}

// witnessObserver runs the tls and dns probes for a target list, returning both
// the snapshots and the compact per-host facts the history store keeps. It uses
// the real probes, so the witness observes with identical code to the sensor.
func witnessObserver(cfg *config.Config) witness.Observer {
	return func(ctx context.Context, targets []string) (map[string]probe.Snapshot, map[string]witness.WitnessTLS) {
		// The witness observes its OWN configured pin list; targets from the
		// sensor were already intersected with it server-side.
		snaps := map[string]probe.Snapshot{}
		facts := map[string]witness.WitnessTLS{}

		if p, ok := probe.Get("tls"); ok {
			s, err := p.Observe(ctx, probe.Inputs{Config: cfg})
			if err == nil {
				snaps["tls"] = s
				facts = tlsFactsFrom(s)
			}
		}
		if p, ok := probe.Get("dns"); ok {
			if s, err := p.Observe(ctx, probe.Inputs{Config: cfg}); err == nil {
				snaps["dns"] = s
			}
		}
		return snaps, facts
	}
}

// tlsFactsFrom pulls the history-relevant fields out of a tls snapshot without
// importing tlsprobe's private type.
func tlsFactsFrom(s probe.Snapshot) map[string]witness.WitnessTLS {
	var payload struct {
		Hosts map[string]struct {
			IssuerO     string `json:"issuer_o"`
			IssuerSPKI  string `json:"issuer_spki"`
			RootSubject string `json:"root_subject"`
			SCTCount    int    `json:"sct_count"`
			Err         string `json:"err"`
		} `json:"hosts"`
	}
	out := map[string]witness.WitnessTLS{}
	if json.Unmarshal(s.Data, &payload) != nil {
		return out
	}
	for host, o := range payload.Hosts {
		if o.Err != "" {
			continue
		}
		out[host] = witness.WitnessTLS{
			IssuerO: o.IssuerO, IssuerSPKI: o.IssuerSPKI,
			RootSubject: o.RootSubject, HasSCT: o.SCTCount > 0,
		}
	}
	return out
}

func witnessServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("witness serve", flag.ExitOnError)
	cfgPath := fs.String("config", "", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	id, err := witness.LoadOrCreateIdentity(witnessKeyDir(cfg), "mitmwatch-witness")
	if err != nil {
		return err
	}

	hist := witness.LoadHistory(historyPath(cfg))

	// The witness's own alert sinks, on its own box: an attacker who silences
	// the sensor cannot silence these.
	sinks, err := alert.Sinks(cfg, os.Stdout)
	if err != nil {
		return err
	}
	silenceAlert := func(sensorID, reason string, since time.Time) {
		a := verdict.Alert{
			Target: sensorID, Score: cfg.Weight("witness/sensor-silent"),
			Band: verdict.BandOf(cfg.Weight("witness/sensor-silent")),
			Findings: []probe.Finding{{
				Probe: "witness", Vector: "witness/sensor-silent", Target: sensorID,
				Score: cfg.Weight("witness/sensor-silent"),
				Title: "Your home sensor stopped reporting",
				Evidence: map[string]string{
					"reason": reason, "quiet_since": since.Format(time.RFC3339),
					"what_to_do": "check the sensor is powered on and connected",
				},
			}},
		}
		for _, s := range sinks {
			s.Send(ctx, a) //nolint:errcheck
		}
	}

	// selfTest: can the witness still reach a couple of its own hosts? If not,
	// the witness is the broken end and must not blame the sensor.
	selfTest := func(ctx context.Context) bool {
		snaps, _ := witnessObserver(cfg)(ctx, cfg.TLS.Pin)
		s, ok := snaps["tls"]
		if !ok {
			return false
		}
		return tlsAnyOK(s)
	}

	fmt.Printf("mitmwatch witness %s\n", version)
	fmt.Printf("  identity  %s\n", id.Pin)
	fmt.Printf("  listen    %s\n", listenOrDefault(cfg.Witness.Listen))
	fmt.Printf("  allowing  %d sensor pin(s)\n", len(cfg.Witness.AllowPins))
	fmt.Printf("  tick      every %s\n", cfg.Witness.Tick())
	fmt.Printf("  sinks     %s\n", sinkList(sinks))
	fmt.Println()

	srv := witness.NewServer(id, cfg, witnessObserver(cfg), hist, silenceAlert, selfTest)
	return srv.Serve(ctx)
}

func witnessKeygen(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("witness keygen", flag.ExitOnError)
	cfgPath := fs.String("config", "", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	id, err := witness.LoadOrCreateIdentity(witnessKeyDir(cfg), "mitmwatch-witness")
	if err != nil {
		return err
	}
	fmt.Printf("identity ready.\n\n  this box's pin: %s\n\n", id.Pin)
	fmt.Println("on the SENSOR, run:  mitmwatch witness pair --addr <this-host>:8443")
	fmt.Println("then bring its pin back here:  mitmwatch witness allow <sensor-pin>")
	return nil
}

func witnessPair(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("witness pair", flag.ExitOnError)
	cfgPath := fs.String("config", "", "config file")
	addr := fs.String("addr", "", "witness host:port")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *addr == "" {
		return errors.New("usage: mitmwatch witness pair --addr host:8443")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	id, err := witness.LoadOrCreateIdentity(witnessKeyDir(cfg), "mitmwatch-sensor")
	if err != nil {
		return err
	}

	fmt.Printf("this sensor's pin: %s\n\n", id.Pin)

	// Dial once and learn the witness pin, then verify by reconnecting with it
	// pinned. A pin that does not actually match the live server is refused
	// rather than written - the top operator footgun.
	witnessPin, err := witness.LearnServerPin(ctx, *addr, id)
	if err != nil {
		return fmt.Errorf("could not reach the witness at %s: %w", *addr, err)
	}
	fmt.Printf("witness pin:      %s\n", witnessPin)
	if err := witness.VerifyServerPin(ctx, *addr, id, witnessPin); err != nil {
		return fmt.Errorf("witness pin did not verify on reconnect: %w", err)
	}

	fmt.Println("\nlink verified. add to this sensor's config:")
	fmt.Printf("\n  [witness]\n  sync = true\n  addr = %q\n  pin  = %q\n\n", *addr, witnessPin)
	fmt.Printf("and on the witness, allow this sensor:\n  mitmwatch witness allow %s\n", id.Pin)
	return nil
}

func witnessAllow(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("witness allow", flag.ExitOnError)
	cfgPath := fs.String("config", "", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pins := fs.Args()
	if len(pins) == 0 {
		return errors.New("usage: mitmwatch witness allow <sensor-pin> [more...]")
	}
	for _, p := range pins {
		if !witness.ValidPin(p) {
			return fmt.Errorf("%q is not a valid pin (want sha256/<64 hex>)", p)
		}
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	// This one command mutates config, so it prints what to persist rather than
	// silently editing a file it may not own.
	have := map[string]bool{}
	for _, p := range cfg.Witness.AllowPins {
		have[p] = true
	}
	merged := append([]string{}, cfg.Witness.AllowPins...)
	added := 0
	for _, p := range pins {
		if !have[p] {
			merged = append(merged, p)
			added++
		}
	}
	fmt.Printf("added %d pin(s). set in the witness config:\n\n  [witness]\n  allow_pins = [\n", added)
	for _, p := range merged {
		fmt.Printf("    %q,\n", p)
	}
	fmt.Println("  ]")
	return nil
}

func witnessHistory(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("witness history", flag.ExitOnError)
	cfgPath := fs.String("config", "", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	hist := witness.LoadHistory(historyPath(cfg))
	recs := hist.Snapshot()
	if len(recs) == 0 {
		fmt.Println("no history yet - the witness records what it observes as it runs")
		return nil
	}
	hosts := make([]string, 0, len(recs))
	for h := range recs {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	only := ""
	if a := fs.Args(); len(a) > 0 {
		only = a[0]
	}
	for _, h := range hosts {
		if only != "" && h != only {
			continue
		}
		r := recs[h]
		fmt.Printf("%s  (%d observations, sct-always=%t)\n", h, r.Obs, r.SCTAlways)
		for org := range r.IssuerOrgs {
			fmt.Printf("    issuer org: %s\n", org)
		}
		for root := range r.Roots {
			fmt.Printf("    root:       %s\n", root)
		}
	}
	return nil
}

func witnessStatus(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("witness status", flag.ExitOnError)
	cfgPath := fs.String("config", "", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	id, err := witness.LoadOrCreateIdentity(witnessKeyDir(cfg), "mitmwatch")
	if err != nil {
		return err
	}
	fmt.Printf("pin:        %s\n", id.Pin)
	fmt.Printf("role:       %s\n", cfg.Sensor.Role)
	if cfg.Witness.Sync {
		fmt.Printf("sensor link: configured -> %s (pin %s)\n", cfg.Witness.Addr, cfg.Witness.Pin)
	} else {
		fmt.Println("sensor link: not configured ([witness] sync=false)")
	}
	fmt.Printf("witness:    listen %s, allowing %d sensor(s)\n",
		listenOrDefault(cfg.Witness.Listen), len(cfg.Witness.AllowPins))
	return nil
}

func historyPath(cfg *config.Config) string {
	if cfg.Witness.HistoryPath != "" {
		return cfg.Witness.HistoryPath
	}
	return filepath.Join(witnessKeyDir(cfg), "history.json")
}

func listenOrDefault(s string) string {
	if s == "" {
		return ":8443"
	}
	return s
}

func sinkList(sinks []alert.Sink) string {
	names := make([]string, 0, len(sinks))
	for _, s := range sinks {
		names = append(names, s.Name())
	}
	sort.Strings(names)
	return joinComma(names)
}

// tlsAnyOK reports whether a tls snapshot has at least one successfully observed
// host, used by the witness self-test.
func tlsAnyOK(s probe.Snapshot) bool {
	var payload struct {
		Hosts map[string]struct {
			Err string `json:"err"`
		} `json:"hosts"`
	}
	if json.Unmarshal(s.Data, &payload) != nil {
		return false
	}
	for _, o := range payload.Hosts {
		if o.Err == "" {
			return true
		}
	}
	return false
}
