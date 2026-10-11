// Package probe defines the detector interface and the registry.
//
// Adding a detection vector is adding one package with an init() that calls
// Register. Probes never alert: they emit Findings, and core/verdict decides
// what that means.
package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/frame"
	"github.com/sizzlorox/mitmwatch/internal/osq"
)

// Snapshot is one probe's observation. The payload stays opaque JSON so the
// baseline store is generic while each probe keeps a strongly typed struct.
type Snapshot struct {
	Probe string          `json:"probe"`
	Time  time.Time       `json:"time"`
	Data  json.RawMessage `json:"data"`

	// Degraded marks an observation the probe could not complete. It must never
	// become a baseline.
	//
	// Without this the runner cannot tell "I looked and the network is clean"
	// from "I could not look", because both arrive as a snapshot with nothing
	// in it. Adopting the second is how a detector blinds itself twice over:
	// the empty view becomes normal, and then the next healthy observation
	// reports the entire real world as newly appeared. A trust store that fails
	// to read once yields thirty-nine separate root-added findings at Critical
	// on the following pass.
	//
	// It is the complement of the runner's freeze rule, not a duplicate: that
	// refuses to absorb a suspicious *change*, this refuses to absorb a
	// *non-observation*. Capture tiers make it load-bearing from phase 1, where
	// a polling source that saw no frames and a genuinely silent LAN are the
	// same empty snapshot.
	Degraded bool   `json:"degraded,omitempty"`
	Err      string `json:"err,omitempty"`
	// Duration is measured by the runner for audit display and is never persisted
	// with a baseline or included in the witness comparison payload.
	Duration time.Duration `json:"-"`
}

// Encode builds a Snapshot from a probe's own payload type.
func Encode(name string, v any) (Snapshot, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return Snapshot{}, fmt.Errorf("probe %s: encode snapshot: %w", name, err)
	}
	return Snapshot{Probe: name, Time: time.Now().UTC(), Data: b}, nil
}

// Incomplete builds a Snapshot carrying whatever the probe did manage to see,
// marked so the runner will not adopt it as a baseline. Probes should still
// pass their partial payload: it is worth reporting, just not worth learning.
func Incomplete(name string, v any, cause error) (Snapshot, error) {
	s, err := Encode(name, v)
	if err != nil {
		return Snapshot{}, err
	}
	s.Degraded = true
	if cause != nil {
		s.Err = cause.Error()
	}
	return s, nil
}

// Decode unmarshals the payload into v. An empty Snapshot decodes to nothing
// and reports false, which is how a probe detects "no baseline yet".
func (s Snapshot) Decode(v any) (bool, error) {
	if len(s.Data) == 0 {
		return false, nil
	}
	if err := json.Unmarshal(s.Data, v); err != nil {
		return false, fmt.Errorf("probe %s: decode snapshot: %w", s.Probe, err)
	}
	return true, nil
}

// Empty reports whether this snapshot holds no observation.
func (s Snapshot) Empty() bool { return len(s.Data) == 0 }

// Finding is a single piece of evidence with a score. Scores accumulate per
// target in core/verdict; one finding is rarely an alert on its own.
type Finding struct {
	Probe string `json:"probe"`
	// Vector is the stable identifier used for scoring, dedup and the
	// plain-language lookup, e.g. "tls/private-root".
	Vector string `json:"vector"`
	// Target is what the finding is about: a hostname, or "network".
	Target string `json:"target"`
	Score  int    `json:"score"`
	Title  string `json:"title"`

	// Identity is what makes this finding *this* finding. It, with the vector
	// and target, is all that Hash covers.
	//
	// It exists because Evidence cannot serve both jobs. Evidence is written
	// for a person reading an alert, so it carries things that move on their
	// own: how many days old a certificate authority is, which serial a
	// rotating leaf currently has, which addresses a CDN answered with this
	// minute. Hashing those made `baseline accept` expire the moment any of
	// them ticked - the user was told "it will not be reported again" and then
	// it was, the next day, under a new hash.
	//
	// Put in here only what a person is really accepting: the root's digest,
	// the issuer, the specific host pair. Leave the rest in Evidence.
	// Empty means the vector and target alone identify it.
	Identity map[string]string `json:"identity,omitempty"`

	// Evidence is shown, never hashed.
	Evidence map[string]string `json:"evidence"`

	// Change marks a finding that reports a difference from the baseline,
	// rather than a condition that is simply true right now.
	//
	// The distinction decides whether the baseline may be updated while the
	// finding stands. Absorbing a change would teach the detector that an
	// attack is the new normal - a root that appeared must never quietly
	// become a root that was always there. Absorbing a persistent state is
	// both safe and necessary, because comparisons that ask "has this been
	// stable?" cannot answer until the state is recorded at least once.
	Change bool `json:"change,omitempty"`
}

// Hash identifies this finding for dedup and for `baseline accept`.
//
// It deliberately covers the vector, the target and Identity only. A finding
// whose identity is unchanged is the same finding however its display evidence
// has moved, so an accept keeps holding; a finding with a different identity -
// a different root, a different issuer - is a different finding and must
// surface even though the user accepted its predecessor.
func (f Finding) Hash() string {
	keys := make([]string, 0, len(f.Identity))
	for k := range f.Identity {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(f.Vector)
	b.WriteByte(0)
	b.WriteString(f.Target)
	for _, k := range keys {
		b.WriteByte(0)
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(f.Identity[k])
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:6])
}

// Inputs is what a probe gets to observe with.
type Inputs struct {
	// Frames is nil for canary probes and at tier 3. Exactly one probe may
	// consume it per pass; a fan-out belongs here when a second capture-fed
	// probe exists, and not before.
	Frames <-chan frame.Frame
	// CaptureWindow bounds how long a capture-fed probe may read for. Zero
	// means do not read at all.
	CaptureWindow time.Duration
	// Baseline is what this probe recorded last time.
	//
	// Observe needs it, not only Compare, because some observations are
	// cumulative: a device inventory is "everything ever seen here", not
	// "whatever answered during the last five seconds". Without this a probe
	// could only ever describe the instant it ran, and the runner would
	// replace the accumulated view with that instant.
	Baseline Snapshot

	Network osq.NetworkIdentity
	Config  *config.Config
}

// CaptureFed is implemented by probes that read Inputs.Frames.
//
// It is an optional interface rather than a method on Probe so that the five
// canary probes stay untouched, and so the runner does not buffer frames for a
// probe that will never read them - a subscriber that never drains is a
// subscriber whose whole window is dropped, counted, and reported as loss that
// did not happen.
type CaptureFed interface {
	ConsumesFrames() bool
}

// WantsFrames reports whether p reads from the capture stream.
func WantsFrames(p Probe) bool {
	c, ok := p.(CaptureFed)
	return ok && c.ConsumesFrames()
}

// WitnessView is the remote witness's corresponding observation, fed into the
// existing Compare methods so cross-vantage rules live beside the local ones
// with no parallel code path.
//
// It is deliberately probe-agnostic: the witness ran the same Observe, so its
// payload decodes into each probe's own snapshot type. A probe that has no
// witness rules simply never reads it.
//
// Every field defaults to the phase-0 behaviour. Configured is false unless a
// witness is set up; Available is false unless a fresh, validated, non-degraded
// observation is present. When both are false, Compare is byte-identical to
// phase 0 - the witness can only ever add findings, never suppress the local
// ones or change them.
type WitnessView struct {
	// Configured reports that a witness is set up ([witness] sync=true with an
	// address and a pin). Distinguishes "no witness" from "witness down".
	Configured bool
	// Available reports that a fresh, validated observation is on hand.
	Available bool
	// ReportDown is set only once the link has been down past its grace period,
	// so a witness reboot does not raise the link-health finding.
	ReportDown bool
	// Err is why the view is unavailable, for evidence.
	Err string
	// ObservedAt is the witness's own timestamp - human-readable evidence only,
	// never a correctness input.
	ObservedAt  time.Time
	CheckTimes  map[string]time.Duration
	CheckStatus map[string]string

	snap   map[string]Snapshot
	stable map[string]bool
}

// NewWitnessView assembles a view. snap is keyed by probe name; stable lists the
// hosts whose witness observation has held identical across enough ticks to be
// trusted as a comparison baseline.
func NewWitnessView(configured, available, reportDown bool, errStr string, observedAt time.Time,
	snap map[string]Snapshot, stable map[string]bool, checkTimes ...map[string]time.Duration) WitnessView {
	v := WitnessView{
		Configured: configured, Available: available, ReportDown: reportDown,
		Err: errStr, ObservedAt: observedAt, snap: snap, stable: stable,
	}
	if len(checkTimes) > 0 {
		v.CheckTimes = checkTimes[0]
	}
	return v
}

// WithCheckStatus attaches the outside observation results for the audit view.
func (w WitnessView) WithCheckStatus(status map[string]string) WitnessView {
	w.CheckStatus = status
	return w
}

// Snapshot returns the witness's snapshot for a probe, and whether it is usable
// (present and the view is available).
func (w WitnessView) Snapshot(name string) (Snapshot, bool) {
	s, ok := w.snap[name]
	return s, ok && w.Available
}

// StableHost reports whether the witness's view of this host has been stable
// long enough to compare against. A rule that scores must gate on this, so a
// transient witness glitch cannot drive a finding.
func (w WitnessView) StableHost(host string) bool {
	return w.Available && w.stable[host]
}

// CompareCtx carries everything Compare needs beyond the two snapshots.
//
// This extends SDD 7.1's Compare(baseline, current, witness): trust level and
// the accept list have to reach the comparison, because the same evidence
// means different things on a `work` profile than on a `public` one.
type CompareCtx struct {
	Config  *config.Config
	Trust   string // home | work | public | unknown
	Network osq.NetworkIdentity
	// Learning is true inside the profile's learning window, where everything
	// below Critical is suppressed.
	Learning bool
	Witness  WitnessView
	// Accepted reports whether the user has already said "this was me" for a
	// finding hash.
	Accepted func(hash string) bool
}

// IsAccepted is nil-safe.
func (c CompareCtx) IsAccepted(hash string) bool {
	return c.Accepted != nil && c.Accepted(hash)
}

// Weight looks up the configured score for a vector.
func (c CompareCtx) Weight(vector string) int { return c.Config.Weight(vector) }

// Probe is one detector.
type Probe interface {
	Name() string
	// Interval is 0 for event-driven probes fed by capture.
	Interval() time.Duration
	Observe(ctx context.Context, in Inputs) (Snapshot, error)
	Compare(baseline, current Snapshot, cc CompareCtx) []Finding
}

var (
	mu       sync.RWMutex
	registry = map[string]Probe{}
)

// Register adds a probe. Called from each probe package's init().
func Register(p Probe) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[p.Name()]; dup {
		panic("probe: duplicate registration for " + p.Name())
	}
	registry[p.Name()] = p
}

// All returns every registered probe, ordered by name for stable output.
func All() []Probe {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]Probe, 0, len(names))
	for _, n := range names {
		out = append(out, registry[n])
	}
	return out
}

// Get returns one probe by name.
func Get(name string) (Probe, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := registry[name]
	return p, ok
}

// Select returns the named probes, or all of them when names is empty. An
// unknown name is an error rather than a silent no-op.
func Select(names []string) ([]Probe, error) {
	if len(names) == 0 {
		return All(), nil
	}
	out := make([]Probe, 0, len(names))
	for _, n := range names {
		p, ok := Get(n)
		if !ok {
			return nil, fmt.Errorf("unknown probe %q (have: %s)", n, strings.Join(Names(), ", "))
		}
		out = append(out, p)
	}
	return out, nil
}

// Names lists registered probe names.
func Names() []string {
	ps := All()
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Name()
	}
	return out
}
