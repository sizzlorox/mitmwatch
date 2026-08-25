package witness

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"crypto/tls"
	"net"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

// SensorObserve is what the sensor hands the Link to answer a tick with its own
// view. It returns the sensor's own snapshots for the report frame.
type SensorObserve func(ctx context.Context, targets []string) map[string]probe.Snapshot

// Link is the sensor's side of the witness protocol. It maintains one dialled
// mTLS connection, receives ticks, judges each on the sensor's OWN monotonic
// clock, tracks per-host stability, and publishes a probe.WitnessView the tls
// Compare reads. It is safe for the sensor cycle to call View() at any time.
type Link struct {
	cfg      *config.Config
	id       *Identity
	observe  SensorObserve
	sensorID string

	view atomic.Pointer[probe.WitnessView]

	mu       sync.Mutex
	streak   map[string]string // host -> last stability hash
	streakN  map[string]int    // host -> consecutive identical ticks
	lastRecv time.Time         // sensor monotonic receipt of the last valid tick
	lastSeq  uint64
	beatSeq  uint64
	down     time.Time // when the link first went down, zero when up
}

// NewLink builds the sensor link. observe supplies the sensor's own view for
// report frames.
func NewLink(cfg *config.Config, id *Identity, observe SensorObserve) *Link {
	l := &Link{
		cfg: cfg, id: id, observe: observe,
		sensorID: sensorIDFor(id),
		streak:   map[string]string{}, streakN: map[string]int{},
		down: time.Now(),
	}
	// Start configured-but-unavailable so the tls probe knows a witness exists.
	l.publish(probe.NewWitnessView(true, false, false, "connecting", time.Time{}, nil, nil))
	return l
}

func sensorIDFor(id *Identity) string {
	// A stable, non-identifying id derived from the sensor's own pin.
	sum := sha256.Sum256([]byte(id.Pin))
	return "sensor-" + hex.EncodeToString(sum[:4])
}

// Run maintains the connection until ctx is done, reconnecting with backoff.
func (l *Link) Run(ctx context.Context) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := l.connect(ctx)
		if ctx.Err() != nil {
			return
		}
		// Mark down and republish so the sensor can report unreachable once the
		// grace passes.
		l.markDown(err)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (l *Link) connect(ctx context.Context) error {
	d := &net.Dialer{Timeout: 15 * time.Second}
	raw, err := tls.DialWithDialer(d, "tcp", l.cfg.Witness.Addr, ClientTLS(l.id, l.cfg.Witness.Pin))
	if err != nil {
		return err
	}
	defer raw.Close()

	enc := NewEncoder(raw)
	dec := NewDecoder(raw)

	targets := l.targets()
	if err := enc.Write(TypeHello, Hello{
		Proto: Proto, SensorID: l.sensorID, Role: l.role(),
		Targets: targets, BeatSec: int(l.cfg.Witness.BeatInterval().Seconds()),
	}); err != nil {
		return err
	}

	// Heartbeat on its own timer, independent of ticks.
	beatCtx, stopBeat := context.WithCancel(ctx)
	defer stopBeat()
	go l.beatLoop(beatCtx, enc)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		f, err := dec.Read()
		if err != nil {
			return err
		}
		if f.T != TypeTick {
			continue
		}
		var tick Tick
		if f.Into(&tick) != nil {
			continue
		}
		l.handleTick(ctx, enc, tick)
	}
}

func (l *Link) beatLoop(ctx context.Context, enc *Encoder) {
	t := time.NewTicker(l.cfg.Witness.BeatInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.mu.Lock()
			l.beatSeq++
			seq := l.beatSeq
			l.mu.Unlock()
			if err := enc.Write(TypeBeat, Beat{Seq: seq}); err != nil {
				return
			}
		}
	}
}

// handleTick validates a tick, updates stability, publishes a view, and answers
// with the sensor's own report.
func (l *Link) handleTick(ctx context.Context, enc *Encoder, tick Tick) {
	l.mu.Lock()
	// Replay guard: a tick's seq must strictly increase.
	if tick.Seq <= l.lastSeq && l.lastSeq != 0 {
		l.mu.Unlock()
		return
	}
	l.lastSeq = tick.Seq
	l.lastRecv = time.Now() // the sensor's OWN clock, the only freshness base
	l.down = time.Time{}

	// Decode the witness's tls snapshot to update per-host stability. The
	// snapshot is opaque here; we only hash the fields the rules score on, which
	// live inside its JSON, so we decode into a minimal shape.
	stable := l.updateStability(tick)
	snaps := map[string]probe.Snapshot{}
	for name, raw := range tick.Snap {
		snaps[name] = decodeSnapshot(name, raw)
	}
	view := probe.NewWitnessView(true, true, false, "", time.Unix(tick.ObservedAtUnix, 0),
		snaps, stable)
	l.mu.Unlock()

	l.publish(view)

	// Answer with the sensor's own observation, for the witness's history/audit.
	if l.observe != nil {
		own := l.observe(ctx, tick.Targets)
		raw := map[string]json.RawMessage{}
		for name, sn := range own {
			if b, err := json.Marshal(sn); err == nil {
				raw[name] = b
			}
		}
		enc.Write(TypeReport, Report{Nonce: tick.Nonce, Snap: raw}) //nolint:errcheck
	}
}

// updateStability advances each host's streak and returns the set of hosts that
// have been stable for at least Confirm() ticks.
func (l *Link) updateStability(tick Tick) map[string]bool {
	raw, ok := tick.Snap[tlsName]
	if !ok {
		return map[string]bool{}
	}
	var s struct {
		Hosts map[string]struct {
			IssuerO        string `json:"issuer_o"`
			IssuerSPKI     string `json:"issuer_spki"`
			RootSubject    string `json:"root_subject"`
			RootInEmbedded bool   `json:"root_in_embedded"`
			SCTCount       int    `json:"sct_count"`
			LeafSPKI       string `json:"leaf_spki"`
			Err            string `json:"err"`
		} `json:"hosts"`
	}
	if json.Unmarshal(raw, &s) != nil {
		return map[string]bool{}
	}

	confirm := l.cfg.Witness.Confirm()
	stable := map[string]bool{}
	seen := map[string]bool{}
	for host, o := range s.Hosts {
		seen[host] = true
		// A host the witness could not observe resets its streak - never trust
		// a comparison built on a witness error.
		if o.Err != "" {
			l.streak[host] = ""
			l.streakN[host] = 0
			continue
		}
		h := fmt.Sprintf("%s|%s|%s|%t|%t|%s",
			o.IssuerO, o.IssuerSPKI, o.RootSubject, o.RootInEmbedded, o.SCTCount > 0, o.LeafSPKI)
		if l.streak[host] == h {
			l.streakN[host]++
		} else {
			l.streak[host] = h
			l.streakN[host] = 1
		}
		if l.streakN[host] >= confirm {
			stable[host] = true
		}
	}
	// Forget hosts the witness stopped reporting.
	for host := range l.streak {
		if !seen[host] {
			delete(l.streak, host)
			delete(l.streakN, host)
		}
	}
	return stable
}

// View returns the current witness view, downgrading to unavailable if the last
// valid tick is older than the freshness window - judged entirely on the
// sensor's own clock, so a manipulated clock or a replayed tick cannot forge
// freshness.
func (l *Link) View() probe.WitnessView {
	v := l.view.Load()
	if v == nil {
		return probe.WitnessView{Configured: l.configured()}
	}
	if !v.Available {
		return *v
	}
	l.mu.Lock()
	stale := time.Since(l.lastRecv) > l.cfg.Witness.Fresh()
	l.mu.Unlock()
	if stale {
		down := probe.NewWitnessView(true, false, l.reportDown(), "no fresh update from the witness",
			v.ObservedAt, nil, nil)
		return down
	}
	return *v
}

func (l *Link) publish(v probe.WitnessView) { l.view.Store(&v) }

func (l *Link) markDown(err error) {
	l.mu.Lock()
	if l.down.IsZero() {
		l.down = time.Now()
	}
	l.mu.Unlock()
	msg := "witness unreachable"
	if err != nil {
		msg = err.Error()
	}
	l.publish(probe.NewWitnessView(true, false, l.reportDown(), msg, time.Time{}, nil, nil))
}

// reportDown reports whether the link has been down long enough to raise the
// sensor's own link-health finding. A brief reconnect (witness reboot) does not.
func (l *Link) reportDown() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.down.IsZero() && time.Since(l.down) > l.cfg.Witness.UnreachableAfter()
}

func (l *Link) targets() []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range l.cfg.TLS.Pin {
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, h := range l.cfg.DNS.Anchors {
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

func (l *Link) role() string {
	if l.cfg.Sensor.Role == "always-on" {
		return "always-on"
	}
	return "roaming"
}

func (l *Link) configured() bool {
	return l.cfg.Witness.Sync && l.cfg.Witness.Addr != "" && l.cfg.Witness.Pin != ""
}

// tlsName / tlsProbeName is the probe key the witness tls snapshot is stored
// under. Kept as a constant here to avoid importing tlsprobe (which would be a
// cycle through the registry).
const tlsName = "tls"

// decodeSnapshot rebuilds a probe.Snapshot from a raw witness payload.
func decodeSnapshot(name string, raw json.RawMessage) probe.Snapshot {
	var s probe.Snapshot
	if json.Unmarshal(raw, &s) == nil && s.Probe != "" {
		return s
	}
	// The witness sent the inner payload rather than a wrapped Snapshot; wrap it.
	return probe.Snapshot{Probe: name, Data: raw}
}

// LearnServerPin dials the witness once without pinning, and returns the pin of
// whatever server answered. Used by `witness pair` to discover the pin, which
// the operator then confirms out of band. This is trust-on-first-use bounded by
// the very next step: VerifyServerPin reconnects WITH the pin enforced.
func LearnServerPin(ctx context.Context, addr string, id *Identity) (string, error) {
	var learned string
	cfg := &tls.Config{
		Certificates:       []tls.Certificate{id.Cert},
		InsecureSkipVerify: true, //nolint:gosec // learning the pin; verified next step
		MinVersion:         tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			p, err := peerPin(rawCerts)
			if err != nil {
				return err
			}
			learned = p
			return nil
		},
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return "", err
	}
	conn.Close()
	if learned == "" {
		return "", errors.New("witness presented no usable certificate")
	}
	return learned, nil
}

// VerifyServerPin reconnects with the pin enforced, proving the pin the operator
// is about to persist actually matches the live server - so a mistyped or
// swapped pin fails here rather than silently never matching later.
func VerifyServerPin(ctx context.Context, addr string, id *Identity, pin string) error {
	d := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, ClientTLS(id, pin))
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}
