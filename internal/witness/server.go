package witness

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

// Observer runs a probe's Observe for a target list and returns the snapshot
// payloads keyed by probe name. The witness and the sensor both use this shape,
// so the witness observes with exactly the code the sensor does - no duplicated
// certificate logic.
type Observer func(ctx context.Context, targets []string) (snaps map[string]probe.Snapshot, tlsFacts map[string]WitnessTLS)

// SilenceAlerter is called when the dead-man's switch decides a sensor has gone
// silent in a way that warrants telling someone, through the witness's own
// alert sinks. It is a function so the server needs no dependency on the alert
// package's concrete types.
type SilenceAlerter func(sensorID, reason string, since time.Time)

// Server is the witness daemon.
type Server struct {
	id       *Identity
	cfg      *config.Config
	observe  Observer
	hist     *History
	alert    SilenceAlerter
	selfTest func(ctx context.Context) bool // does the witness's own uplink still work?
}

// NewServer builds a witness server. selfTest lets the watchdog confirm the
// witness's own uplink before blaming the sensor for silence.
func NewServer(id *Identity, cfg *config.Config, observe Observer, hist *History,
	alert SilenceAlerter, selfTest func(context.Context) bool) *Server {
	return &Server{id: id, cfg: cfg, observe: observe, hist: hist, alert: alert, selfTest: selfTest}
}

// Serve binds the configured listener and serves until ctx is done.
func (s *Server) Serve(ctx context.Context) error {
	if len(s.cfg.Witness.AllowPins) == 0 {
		return fmt.Errorf("witness: no allow_pins configured; run `mitmwatch witness allow <sensor-pin>` first")
	}
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", listenAddr(s.cfg.Witness.Listen))
	if err != nil {
		return err
	}
	tln := tls.NewListener(ln, ServerTLS(s.id, s.cfg.Witness.AllowPins))
	return s.serveOn(ctx, tln)
}

// serveOn serves on an already-bound TLS listener. Split out so a test can pass
// a listener on a known port.
func (s *Server) serveOn(ctx context.Context, tln net.Listener) error {
	defer tln.Close()
	go func() {
		<-ctx.Done()
		tln.Close()
	}()

	for {
		conn, err := tln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				// A single bad handshake (unpinned client, scan) must not stop
				// the witness. Log-and-continue.
				continue
			}
		}
		go s.session(ctx, conn)
	}
}

// session handles one sensor connection: hello, then a ticker of observations,
// while ingesting the sensor's reports and beats, with a watchdog on silence.
func (s *Server) session(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second)) // until hello arrives

	dec := NewDecoder(conn)
	enc := NewEncoder(conn)

	first, err := dec.Read()
	if err != nil || first.T != TypeHello {
		return
	}
	var hello Hello
	if err := first.Into(&hello); err != nil || hello.Proto != Proto {
		return
	}

	// SSRF guard: observe only hosts the witness is configured for. A compromised
	// sensor cannot steer the witness at arbitrary targets.
	targets, refused := s.filterTargets(hello.Targets)
	conn.SetDeadline(time.Time{}) // long-lived from here

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Liveness shared between the reader and the watchdog.
	live := &liveness{lastBeat: time.Now(), role: hello.Role}

	// Reader: ingest reports, beats, bye.
	readErr := make(chan error, 1)
	go func() { readErr <- s.readLoop(dec, live) }()

	// Ticker: observe and push.
	interval := s.cfg.Witness.Tick()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Watchdog on silence, only for always-on sensors.
	if hello.Role == "always-on" {
		go s.watchdog(sctx, hello.SensorID, live)
	}

	// Push an immediate first tick so a freshly-paired sensor gets data without
	// waiting a full interval.
	s.pushTick(enc, targets, refused)

	for {
		select {
		case <-sctx.Done():
			return
		case <-readErr:
			// The connection ended (EOF, reset, or bye). The watchdog reads the
			// last-beat time to decide whether that silence warrants an alert.
			return
		case <-ticker.C:
			if err := s.pushTick(enc, targets, refused); err != nil {
				return
			}
		}
	}
}

func (s *Server) pushTick(enc *Encoder, targets, refused []string) error {
	nonce := make([]byte, 16)
	rand.Read(nonce) //nolint:errcheck // crypto/rand does not fail in practice

	snaps, facts := s.observe(context.Background(), targets)
	for host, f := range facts {
		s.hist.Record(host, f)
	}
	_ = s.hist.Save() // best effort; a failed save loses only the extra guard

	// Send the inner probe payload, not the wrapped Snapshot: the sensor's
	// stability decode and the tls Compare both read the payload's own fields
	// (hosts, issuer, ...), and wrapping them under probe/time/data would bury
	// those one level deeper than every reader expects.
	raw := map[string]json.RawMessage{}
	for name, sn := range snaps {
		if len(sn.Data) > 0 {
			raw[name] = sn.Data
		}
	}
	return enc.Write(TypeTick, Tick{
		Nonce:          hex.EncodeToString(nonce),
		Seq:            s.nextSeq(),
		Targets:        targets,
		Refused:        refused,
		Snap:           raw,
		ObservedAtUnix: time.Now().Unix(),
	})
}

func (s *Server) readLoop(dec *Decoder, live *liveness) error {
	for {
		f, err := dec.Read()
		if err != nil {
			return err
		}
		switch f.T {
		case TypeBeat:
			var b Beat
			if f.Into(&b) == nil {
				live.beat(b.Seq)
			}
		case TypeReport:
			live.report()
		case TypeBye:
			live.markBye()
			return io.EOF
		}
	}
}

// watchdog disambiguates silence rather than alarming on it blindly.
func (s *Server) watchdog(ctx context.Context, sensorID string, live *liveness) {
	grace := s.cfg.Witness.ReconnectAfter()
	check := 30 * time.Second
	t := time.NewTicker(check)
	defer t.Stop()

	alerted := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			st := live.snapshot()
			if st.byeReceived {
				return // planned stop
			}
			quiet := time.Since(st.lastBeat)
			if quiet < grace {
				alerted = false
				continue
			}
			// Beats stopped but reports still arriving: only the beat path
			// broke, the sensor is alive. Not an alarm.
			if st.lastReport.After(st.lastBeat) {
				continue
			}
			// The witness's own uplink degraded: the witness is the broken end,
			// not the sensor. Not an alarm.
			if s.selfTest != nil && !s.selfTest(ctx) {
				continue
			}
			if !alerted {
				s.alert(sensorID,
					fmt.Sprintf("no signal for %s; could be power loss, an internet outage, or something blocking the sensor", quiet.Round(time.Minute)),
					st.lastBeat)
				alerted = true
			}
		}
	}
}

func (s *Server) filterTargets(want []string) (targets, refused []string) {
	allow := map[string]bool{}
	for _, h := range s.cfg.TLS.Pin {
		allow[h] = true
	}
	for _, h := range s.cfg.DNS.Anchors {
		allow[h] = true
	}
	for _, h := range want {
		if allow[h] {
			targets = append(targets, h)
		} else {
			refused = append(refused, h)
		}
	}
	return targets, refused
}

var seqMu sync.Mutex
var seqCounter uint64

func (s *Server) nextSeq() uint64 {
	seqMu.Lock()
	defer seqMu.Unlock()
	seqCounter++
	return seqCounter
}

// liveness tracks a session's beats, reports, and close for the watchdog.
type liveness struct {
	mu          sync.Mutex
	lastBeat    time.Time
	lastReport  time.Time
	lastSeq     uint64
	byeReceived bool
	role        string
}

func (l *liveness) beat(seq uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if seq <= l.lastSeq && l.lastSeq != 0 {
		return // replayed beat; ignore
	}
	l.lastSeq = seq
	l.lastBeat = time.Now()
}
func (l *liveness) report() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lastReport = time.Now()
}
func (l *liveness) markBye() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.byeReceived = true
}

type liveSnap struct {
	lastBeat, lastReport time.Time
	byeReceived          bool
}

func (l *liveness) snapshot() liveSnap {
	l.mu.Lock()
	defer l.mu.Unlock()
	return liveSnap{lastBeat: l.lastBeat, lastReport: l.lastReport, byeReceived: l.byeReceived}
}

func listenAddr(s string) string {
	if s == "" {
		return ":8443"
	}
	return s
}
