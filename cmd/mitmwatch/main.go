// Command mitmwatch detects interception of network traffic.
//
// Phase 0 ships the one-shot canary commands: check, doctor, baseline and
// profiles. The sensor, witness and agent daemons arrive in later phases.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/capture"
	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/core/alert"
	"github.com/sizzlorox/mitmwatch/internal/core/baseline"
	"github.com/sizzlorox/mitmwatch/internal/core/verdict"
	"github.com/sizzlorox/mitmwatch/internal/osq"
	"github.com/sizzlorox/mitmwatch/internal/probe"
	"github.com/sizzlorox/mitmwatch/internal/roots"
	"github.com/sizzlorox/mitmwatch/internal/witness"

	// Probes register themselves.
	_ "github.com/sizzlorox/mitmwatch/internal/probe/arpprobe"
	_ "github.com/sizzlorox/mitmwatch/internal/probe/clockprobe"
	_ "github.com/sizzlorox/mitmwatch/internal/probe/dhcpprobe"
	_ "github.com/sizzlorox/mitmwatch/internal/probe/dnsprobe"
	_ "github.com/sizzlorox/mitmwatch/internal/probe/nameresprobe"
	_ "github.com/sizzlorox/mitmwatch/internal/probe/ndprobe"
	_ "github.com/sizzlorox/mitmwatch/internal/probe/sslstrip"
	_ "github.com/sizzlorox/mitmwatch/internal/probe/tlsprobe"
	"github.com/sizzlorox/mitmwatch/internal/probe/truststore"
)

var version = "0.2.0-phase2"

// Exit codes. `check` returning 1 on findings is what makes it usable from a
// cron job or a monitoring system.
const (
	exitClean    = 0
	exitFindings = 1
	exitError    = 2
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitError)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "check":
		err = cmdCheck(ctx, os.Args[2:])
	case "doctor":
		err = cmdDoctor(ctx, os.Args[2:])
	case "baseline":
		err = cmdBaseline(ctx, os.Args[2:])
	case "profiles":
		err = cmdProfiles(ctx, os.Args[2:])
	case "sensor":
		err = cmdSensor(ctx, os.Args[2:])
	case "witness":
		err = cmdWitness(ctx, os.Args[2:])
	case "agent", "service":
		err = fmt.Errorf("%q is not implemented yet (phase %s)", os.Args[1], phaseOf(os.Args[1]))
	case "version", "-v", "--version":
		fmt.Println("mitmwatch", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(exitError)
	}

	var fe findingsError
	switch {
	case errors.As(err, &fe):
		os.Exit(exitFindings)
	case err != nil:
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(exitError)
	}
}

func phaseOf(cmd string) string {
	switch cmd {
	case "sensor":
		return "1"
	case "witness":
		return "2"
	case "agent", "service":
		return "3"
	}
	return "?"
}

func usage() {
	fmt.Fprint(os.Stderr, `mitmwatch - detect interception of your network traffic

usage:
  mitmwatch sensor                run continuously, alerting as things are found
  mitmwatch check [probe...]      run every probe once; exit 1 if anything was found
  mitmwatch doctor                what is covered on this host, and what is not
  mitmwatch baseline show|reset|accept <hash>
  mitmwatch profiles list|trust <key> <home|work|public|unknown>
  mitmwatch version

flags (check, doctor, baseline, profiles):
  --config <path>       config file (default: per-user config dir)
  --profile-dir <path>  where learned baselines live

probes: `+strings.Join(probe.Names(), ", ")+"\n")
}

// findingsError signals "ran fine, found something", which is exit 1 rather
// than an error.
type findingsError struct{ n int }

func (f findingsError) Error() string { return fmt.Sprintf("%d finding(s)", f.n) }

// env is everything a command needs after the common setup.
type env struct {
	cfg     *config.Config
	store   *baseline.Store
	net     osq.NetworkIdentity
	netErr  error
	profile *baseline.Profile
	fresh   bool
	dash    *webState

	// recent holds each probe's most recent findings, so the sensor can
	// evaluate the whole world every cycle rather than only the probes that
	// were due. erroredThisPass records which probes failed this cycle, so a
	// failure keeps the previous view instead of clearing it.
	recent          map[string]recentFindings
	erroredThisPass map[string]bool
	// observedThisPass is what each probe actually saw this cycle, adopted into
	// the baseline or not. The device history reads it rather than the stored
	// snapshot: the baseline refuses to adopt an observation that reports an
	// unabsorbed change, so at exactly the moment an attacker appears the
	// stored view is still the world as it was before.
	observedThisPass map[string]probe.Snapshot
	link             *witness.Link
	// firstDeliver guards the cooldown Forget on the first cycle after start,
	// when the in-memory finding union is empty and would otherwise clear
	// cooldown state it has no basis to clear. Set true at construction.
	firstDeliver bool

	// Dashboard read-model state, maintained across cycles by the sensor.
	tier        string               // friendly capture-tier label ("the wire" / "device tables")
	since       time.Time            // when this sensor process started, for uptime
	lastCycle   time.Time            // when the last completed cycle stamped its sightings
	events      []baseline.Event     // bounded activity log, oldest first, persisted
	eventsTotal int                  // how many entries the log holds in all
	eventsDirty bool                 // the log changed and needs writing
	alerted     map[string]raised    // targets currently in an actionable alert, for raise/clear
	heldSeen    map[string]bool      // targets currently held back, so each is logged once
	sawLearning bool                 // observed the learning window while it was open
	learnedOnce bool                 // emitted the "finished learning" event already
	witnessUp   bool                 // last witness-link state, for connect/disconnect events
	nameCache   map[string]nameEntry // reverse-DNS device names, cached
}

// recentFindings is one probe's last output with an expiry.
type recentFindings struct {
	at       time.Time
	ttl      time.Duration
	findings []probe.Finding
}

// parseArgs makes flags work on either side of the positional arguments.
// Go's flag package stops at the first non-flag word, so `baseline accept
// <hash> --profile-dir X` would silently ignore the flag and write to the
// default store - a footgun with real consequences for a tool whose whole job
// is to be trusted about where its state lives.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var lead []string
	rest := args
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			lead, rest = args[:i], args[i:]
			break
		}
		if i == len(args)-1 {
			lead, rest = args, nil
		}
	}
	if err := fs.Parse(rest); err != nil {
		return nil, err
	}
	return append(lead, fs.Args()...), nil
}

func commonFlags(fs *flag.FlagSet) (*string, *string) {
	return fs.String("config", "", "path to config file"),
		fs.String("profile-dir", "", "directory for learned baselines")
}

// identifyNetwork is a seam so the sensor can re-identify each cycle without
// repeating setup's config and store work.
func identifyNetwork(ctx context.Context) (osq.NetworkIdentity, error) {
	return osq.Identify(ctx)
}

func setup(ctx context.Context, cfgPath, profileDir string) (*env, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	store, err := baseline.Open(profileDir)
	if err != nil {
		return nil, err
	}
	n, netErr := osq.Identify(ctx)

	window := time.Duration(cfg.Learning.WindowMin) * time.Minute
	if window <= 0 {
		window = 10 * time.Minute
	}
	prof, fresh, err := store.Load(n, window)
	if err != nil {
		return nil, err
	}
	return &env{cfg: cfg, store: store, net: n, netErr: netErr, profile: prof, fresh: fresh, firstDeliver: true}, nil
}

// witnessView returns the current cross-vantage view, or a zero (unconfigured)
// view when no link is running - which makes every probe's Compare behave
// exactly as it did in phase 0.
func (e *env) witnessView() probe.WitnessView {
	if e.link == nil {
		return probe.WitnessView{}
	}
	return e.link.View()
}

func (e *env) compareCtx() probe.CompareCtx {
	return probe.CompareCtx{
		Config:   e.cfg,
		Trust:    e.profile.Trust,
		Network:  e.net,
		Learning: e.profile.Learning(),
		Witness:  e.witnessView(),
		Accepted: e.profile.IsAccepted,
	}
}

// adoptable reports whether an observation may become the new baseline.
//
// Two independent reasons say no, and neither implies the other: it is not a
// real observation, or it reports a change that must not be absorbed.
func adoptable(snap probe.Snapshot, fs []probe.Finding, cc probe.CompareCtx) bool {
	return !snap.Degraded && !freezes(fs, cc)
}

// freezes reports whether this observation must be kept OUT of the baseline.
//
// Only an unaccepted *change* freezes it. Absorbing a change would teach the
// detector that an attack is the new normal - a certificate authority that
// just appeared must never quietly become one that was always there.
//
// A persistent *state* is recorded instead of frozen, and that distinction
// matters more than it looks. Freezing on state deadlocked the managed-laptop
// case: tls/private-root scores 70, so the snapshot was never written, so the
// baseline never showed the corporate root, so the rule that softens a *stable*
// private root on a `work` profile could never see one - and the laptop it was
// written for stayed Critical on every host, every five minutes, forever.
//
// Accepted findings do not freeze either. "This was me" has to reach the
// baseline, or the snapshot stays stale for as long as the accepted condition
// lasts and every later comparison is made against an increasingly old view.
func freezes(fs []probe.Finding, cc probe.CompareCtx) bool {
	for _, f := range fs {
		if f.Change && verdict.BandOf(f.Score) >= verdict.High && !cc.IsAccepted(f.Hash()) {
			return true
		}
	}
	return false
}

func cmdCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	cfgPath, profileDir := commonFlags(fs)
	quiet := fs.Bool("quiet", false, "print nothing when clean")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}

	e, err := setup(ctx, *cfgPath, *profileDir)
	if err != nil {
		return err
	}
	probes, err := probe.Select(pos)
	if err != nil {
		return err
	}

	findings, probeErrs := e.pass(ctx, probes)
	res := verdict.Evaluate(findings, e.compareCtx())

	// Validate the sinks before doing anything else with them: a sink the user
	// believes is active but is not means alerts vanish silently, which is the
	// one failure this must never have.
	if _, err := alert.Sinks(e.cfg, io.Discard); err != nil {
		return err
	}

	if !*quiet || len(res.Alerts) > 0 {
		fmt.Printf("network: %s  profile: %s  trust: %s\n",
			e.net.Label(), e.profile.Key, e.profile.Trust)
		if e.profile.Learning() {
			fmt.Printf("learning this network - %s left, only critical findings are shown\n",
				e.profile.LearningLeft().Round(time.Second))
		}
		fmt.Println()
	}

	for _, err := range e.deliver(ctx, res, findings, os.Stdout) {
		fmt.Fprintln(os.Stderr, "alert:", err)
	}

	// Saved after delivery, not before: deliver records which findings were
	// pushed, and that state has to outlive the process or the cooldown resets
	// on every run.
	if err := e.store.Save(e.profile); err != nil {
		return err
	}

	// Suppressions are shown, never hidden: a detector that quietly withholds
	// what it found cannot be trusted about what it did not find. --quiet is
	// the one exception, and only while nothing has actually alerted.
	if len(res.Held) > 0 && (!*quiet || len(res.Alerts) > 0) {
		fmt.Printf("held back (%s):\n", res.Held[0].Suppressed)
		for _, a := range res.Held {
			fmt.Printf("  %-28s score=%-4d %s\n", a.Target, a.Score, vectorList(a))
		}
		fmt.Println()
	}

	for _, err := range probeErrs {
		fmt.Fprintln(os.Stderr, "probe error:", err)
	}

	switch {
	case len(res.Alerts) > 0:
		fmt.Printf("worst: %s\n", strings.ToUpper(res.Max().String()))
	case len(res.Held) > 0 && !*quiet:
		// "all clear" would contradict the list printed immediately above it.
		fmt.Printf("nothing to alert on yet - %d finding(s) held back, listed above\n", len(res.Held))
	case !*quiet:
		fmt.Println("all clear - nothing found on this network")
	}

	if len(res.Alerts) > 0 {
		return findingsError{n: len(res.Alerts)}
	}
	return nil
}

func vectorList(a verdict.Alert) string {
	seen := map[string]bool{}
	var out []string
	for _, f := range a.Findings {
		if !seen[f.Vector] {
			seen[f.Vector] = true
			out = append(out, f.Vector)
		}
	}
	return strings.Join(out, " ")
}

func cmdDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	cfgPath, profileDir := commonFlags(fs)
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	e, err := setup(ctx, *cfgPath, *profileDir)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	row := func(k string, v any) { fmt.Fprintf(w, "  %s\t%v\n", k, v) }

	fmt.Fprintln(w, "mitmwatch", version)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "config")
	row("path", e.cfg.Path())
	row("loaded", boolWord(e.cfg.Loaded(), "yes", "no - using built-in defaults"))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "trust anchor")
	row("embedded roots", fmt.Sprintf("%d certificates", roots.Count()))
	row("bundle date", dateOr(roots.BundleDate()))
	row("bundle sha256", roots.SHA256())
	row("note", "verify this digest against curl.se/ca/cacert.pem.sha256 from a host you know is not intercepted")
	// The counts behind the truststore thresholds. They differ enormously by
	// platform - Windows ships a long code-signing tail, most Linux images ship
	// Mozilla's set and nothing else - so seeing them is how you tell that the
	// filter is still discriminating rather than matching everything or nothing.
	if s, ok := truststore.Summarize(e.profile.Snapshots["truststore"]); ok {
		if s.Err != "" {
			row("local trust store", "UNREADABLE: "+s.Err)
		} else {
			row("local trust store", fmt.Sprintf(
				"%d roots, %d not in the bundle, %d of those can vouch for a website",
				s.Total, s.NotInMozilla, s.ServerAuthExtra))
		}
	} else {
		row("local trust store", "not measured yet - run `mitmwatch check` once")
	}
	fmt.Fprintln(w)

	src, err := capture.Open(e.cfg.Sensor.Interfaces)
	if err != nil {
		return err
	}
	defer src.Close()
	fmt.Fprintln(w, "capture")
	row("tier", src.Tier())
	row("coverage", src.Tier().Coverage())
	if n := src.Iface(); n != "" {
		row("interface", n)
	}
	row("listen window", e.cfg.CaptureWindow().String()+" per pass")
	if r := src.Reason(); r != "" {
		row("why", r)
	}
	if err := src.Err(); err != nil {
		row("error", err)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "network")
	if e.netErr != nil {
		row("query error", e.netErr)
	}
	row("label", e.net.Label())
	row("interface", orNone(e.net.Iface))
	row("ssid", orNone(e.net.SSID))
	row("gateway", orNone(e.net.GatewayIP)+" at "+orNone(e.net.GatewayMAC))
	row("dhcp server", orNone(e.net.DHCPServer))
	row("resolvers", orNone(strings.Join(e.net.Resolvers, ", ")))
	if len(e.net.Missing) > 0 {
		row("could not determine", strings.Join(e.net.Missing, ", "))
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "profile")
	row("key", e.profile.Key)
	row("trust", e.profile.Trust)
	row("first seen", dateOr(e.profile.FirstSeen))
	if e.profile.Learning() {
		row("learning", e.profile.LearningLeft().Round(time.Second).String()+" left")
	} else {
		row("learning", "complete")
	}
	row("baselines held", fmt.Sprintf("%d probe(s)", len(e.profile.Snapshots)))
	row("accepted findings", len(e.profile.Accepted))
	row("stored in", e.store.Path())
	fmt.Fprintln(w)

	fmt.Fprintln(w, "probes")
	for _, p := range probe.All() {
		iv := "event-driven"
		if p.Interval() > 0 {
			iv = "every " + p.Interval().String()
		}
		row(p.Name(), iv)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "witness (outside comparison)")
	switch {
	case !e.cfg.Witness.Sync:
		row("status", "not configured - run `mitmwatch witness pair` to add an outside vantage point")
	case e.cfg.Witness.Addr == "" || e.cfg.Witness.Pin == "":
		row("status", "sync on but addr or pin missing")
	default:
		row("addr", e.cfg.Witness.Addr)
		row("pin", e.cfg.Witness.Pin)
		row("tick", e.cfg.Witness.Tick().String())
		row("confirm", fmt.Sprintf("%d ticks before a host is scored", e.cfg.Witness.Confirm()))
		row("note", "the sensor process reports live link health; this only shows configuration")
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "egress - every host this binary will contact")
	row("tls", strings.Join(e.cfg.TLS.Pin, ", "))
	row("dns anchors", strings.Join(e.cfg.DNS.Anchors, ", "))
	row("doh", strings.Join(e.cfg.DNS.DoH, ", "))
	row("sslstrip", strings.Join(e.cfg.SSLStrip.Hosts, ", "))
	row("ntp", strings.Join(e.cfg.Clock.NTP, ", "))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "not covered on this host")
	for _, s := range gaps(src.Tier()) {
		fmt.Fprintf(w, "  - %s\n", s)
	}

	return w.Flush()
}

// gaps is the honest list of what this configuration cannot see. `doctor`
// exists to say this out loud rather than let a green screen imply coverage
// that is not there.
// Tier3PollingOnly aliases the tier for readability in gaps().
const Tier3PollingOnly = capture.Tier3Polling

func gaps(t capture.Tier) []string {
	out := []string{
		"passive eavesdropping - a silent tap leaves no trace and is out of scope by design",
		"host-level attacks (injected root CA, forced proxy, hosts file, ssh keys) - needs the agent, phase 3",
		"comparison against an outside vantage point - needs the witness, phase 2",
	}
	switch t {
	case Tier3PollingOnly:
		out = append(out,
			"arp spoofing aimed at OTHER devices - without capture the arp probe reads only this "+
				"host's own neighbour table, so it sees a spoof aimed at this sensor but not one "+
				"aimed only at your laptop. A headless sensor resolves few neighbours (measured: 2 "+
				"on a pi vs 40 on a desktop sharing the segment), which narrows it further",
			"rogue dhcp, ipv6 router advertisements, and name-resolution poisoning (llmnr/nbt-ns/mdns)")
	default:
		out = append(out,
			"anything that happens between listen windows - capture samples rather than runs "+
				"continuously, which is enough for arp poisoning because it repeats about once a "+
				"second, and not enough for a one-off event",
			"wi-fi attacks (evil-twin ap, deauth floods) - these live below the ethernet frame "+
				"and need a radio in monitor mode, which a wired sensor cannot provide (phase 4)")
	}
	return out
}

func cmdBaseline(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("baseline", flag.ExitOnError)
	cfgPath, profileDir := commonFlags(fs)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	sub := argAt(pos, 0)
	if sub == "" {
		return errors.New("usage: mitmwatch baseline show|reset|accept <hash>")
	}
	e, err := setup(ctx, *cfgPath, *profileDir)
	if err != nil {
		return err
	}

	switch sub {
	case "show":
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintf(w, "profile\t%s (%s)\n", e.profile.Key, e.profile.Label)
		fmt.Fprintf(w, "trust\t%s\n", e.profile.Trust)
		fmt.Fprintf(w, "first seen\t%s\n", dateOr(e.profile.FirstSeen))
		fmt.Fprintf(w, "learning\t%s\n", boolWord(e.profile.Learning(),
			e.profile.LearningLeft().Round(time.Second).String()+" left", "complete"))
		fmt.Fprintln(w, "\nbaselines held")
		for _, p := range probe.All() {
			s := e.profile.Snapshots[p.Name()]
			if s.Empty() {
				fmt.Fprintf(w, "  %s\tnone yet\n", p.Name())
				continue
			}
			fmt.Fprintf(w, "  %s\t%s (%d bytes)\n", p.Name(), dateOr(s.Time), len(s.Data))
		}
		if len(e.profile.Accepted) > 0 {
			fmt.Fprintln(w, "\naccepted findings")
			for h, a := range e.profile.Accepted {
				fmt.Fprintf(w, "  %s\t%s on %s (%s)\n", h, a.Vector, a.Target, dateOr(a.When))
			}
		}
		return w.Flush()

	case "reset":
		if err := e.store.Reset(e.profile.Key); err != nil {
			return err
		}
		fmt.Printf("reset profile %s - the next check relearns this network\n", e.profile.Key)
		fmt.Println("  the device history in it is discarded; the activity log is kept")
		return nil

	case "accept":
		hash := argAt(pos, 1)
		if hash == "" {
			return errors.New("usage: mitmwatch baseline accept <hash>")
		}
		e.profile.Accept(hash, baseline.Accept{Note: "accepted from the command line"})
		if err := e.store.Save(e.profile); err != nil {
			return err
		}
		fmt.Printf("accepted %s on profile %s - it will not be reported again\n", hash, e.profile.Key)
		return nil
	}
	return fmt.Errorf("unknown subcommand %q", sub)
}

func cmdProfiles(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("profiles", flag.ExitOnError)
	cfgPath, profileDir := commonFlags(fs)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	e, err := setup(ctx, *cfgPath, *profileDir)
	if err != nil {
		return err
	}

	switch argAt(pos, 0) {
	case "", "list":
		ps, err := e.store.List()
		if err != nil {
			return err
		}
		if len(ps) == 0 {
			fmt.Println("no profiles yet - run `mitmwatch check` once")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "KEY\tLABEL\tTRUST\tGATEWAY\tLAST SEEN")
		for _, p := range ps {
			marker := ""
			if p.Key == e.profile.Key {
				marker = " (current)"
			}
			fmt.Fprintf(w, "%s\t%s%s\t%s\t%s\t%s\n",
				p.Key, p.Label, marker, p.Trust, p.Network.GatewayIP, dateOr(p.LastSeen))
		}
		return w.Flush()

	case "trust":
		key, level := argAt(pos, 1), argAt(pos, 2)
		if key == "" || level == "" {
			return errors.New("usage: mitmwatch profiles trust <key> <home|work|public|unknown>")
		}
		if !baseline.ValidTrust(level) {
			return fmt.Errorf("unknown trust level %q (want home, work, public or unknown)", level)
		}
		// Read-modify-write the stored file, not a copy handed out by List: a
		// running sensor rewrites the same profile every couple of minutes, so
		// saving a listing taken a moment ago rolls back everything learned
		// since - the device history and the notification cooldowns with it.
		p, err := e.store.SetTrust(key, level)
		if err != nil {
			return err
		}
		fmt.Printf("profile %s (%s) is now trusted as %q\n", p.Key, p.Label, level)
		return nil
	}
	return fmt.Errorf("unknown subcommand %q", argAt(pos, 0))
}

func argAt(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

func boolWord(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func dateOr(t time.Time) string {
	if t.IsZero() {
		return "(unknown)"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}
