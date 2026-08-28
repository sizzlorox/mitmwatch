// Package baseline stores what "normal" looks like, per network profile.
//
// Baselines are learned, never shipped. A profile is keyed by the network
// identity, so walking from home to a cafe switches profiles rather than
// raising every difference as a finding.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/osq"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

// Trust levels. An unknown network gets the strictest treatment.
const (
	TrustHome    = "home"
	TrustWork    = "work"
	TrustPublic  = "public"
	TrustUnknown = "unknown"
)

// ValidTrust reports whether s is a trust level.
func ValidTrust(s string) bool {
	switch s {
	case TrustHome, TrustWork, TrustPublic, TrustUnknown:
		return true
	}
	return false
}

// Accept records a user saying "this was me" about a specific finding.
type Accept struct {
	Vector string    `json:"vector"`
	Target string    `json:"target"`
	When   time.Time `json:"when"`
	Note   string    `json:"note,omitempty"`
}

// Profile is one network's learned normal.
type Profile struct {
	Key        string                    `json:"key"`
	Label      string                    `json:"label"`
	Trust      string                    `json:"trust"`
	FirstSeen  time.Time                 `json:"first_seen"`
	LastSeen   time.Time                 `json:"last_seen"`
	LearnUntil time.Time                 `json:"learn_until"`
	Network    osq.NetworkIdentity       `json:"network"`
	Snapshots  map[string]probe.Snapshot `json:"snapshots"`
	Accepted   map[string]Accept         `json:"accepted"`

	// Notified records when each finding was last pushed to a notification
	// sink, so a cooldown survives a restart. A cooldown that resets when the
	// process does is not one: the sensor restarts on every upgrade, and a
	// crash loop would become a notification loop.
	Notified map[string]time.Time `json:"notified,omitempty"`

	// Devices is the history of hardware seen on this network, keyed by MAC.
	// A record for people to read; nothing in detection may consult it. See
	// devices.go.
	Devices map[string]Device `json:"devices,omitempty"`
}

// Learning reports whether the profile is still inside its learning window,
// during which everything below Critical is suppressed.
func (p *Profile) Learning() bool { return time.Now().Before(p.LearnUntil) }

// LearningLeft is how much of the window remains, for the CLI and dashboard.
func (p *Profile) LearningLeft() time.Duration {
	d := time.Until(p.LearnUntil)
	if d < 0 {
		return 0
	}
	return d
}

// IsAccepted reports whether a finding hash was accepted by the user.
func (p *Profile) IsAccepted(hash string) bool {
	_, ok := p.Accepted[hash]
	return ok
}

// Accept marks a finding hash as expected on this network.
func (p *Profile) Accept(hash string, a Accept) {
	if p.Accepted == nil {
		p.Accepted = map[string]Accept{}
	}
	if p.Notified == nil {
		p.Notified = map[string]time.Time{}
	}
	a.When = time.Now().UTC()
	p.Accepted[hash] = a
}

// Store is a directory of profile files.
type Store struct{ dir string }

// Dir is where profiles live: system-wide when running as root on unix, per
// user otherwise.
func Dir() string {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		return "/var/lib/mitmwatch/profiles"
	}
	d, err := os.UserConfigDir()
	if err != nil {
		return "profiles"
	}
	return filepath.Join(d, "mitmwatch", "profiles")
}

// Open returns a store rooted at dir, creating it if needed. Empty dir means
// Dir().
func Open(dir string) (*Store, error) {
	if dir == "" {
		dir = Dir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	return &Store{dir: dir}, nil
}

// Path is the store's directory.
func (s *Store) Path() string { return s.dir }

func (s *Store) file(key string) string { return filepath.Join(s.dir, key+".json") }

// Load returns the profile for this network, creating a fresh one (and
// starting its learning window) the first time the network is seen.
func (s *Store) Load(n osq.NetworkIdentity, learnWindow time.Duration) (*Profile, bool, error) {
	key := n.Key()
	b, err := os.ReadFile(s.file(key))
	if os.IsNotExist(err) {
		now := time.Now().UTC()
		p := &Profile{
			Key:        key,
			Label:      n.Label(),
			Trust:      TrustUnknown,
			FirstSeen:  now,
			LastSeen:   now,
			LearnUntil: now.Add(learnWindow),
			Network:    n,
			Snapshots:  map[string]probe.Snapshot{},
			Accepted:   map[string]Accept{},
			Notified:   map[string]time.Time{},
			Devices:    map[string]Device{},
		}
		return p, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("baseline: %w", err)
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, false, fmt.Errorf("baseline %s: %w", key, err)
	}
	p.fillMaps()
	// The network identity can gain fields (a resolver list arriving late)
	// without changing the key; keep the freshest view.
	p.Network = n
	p.Label = n.Label()
	p.LastSeen = time.Now().UTC()
	return &p, false, nil
}

// fillMaps replaces the nil maps a profile written by an older version - or one
// whose JSON simply omitted them - decodes with.
//
// A nil map in Go reads perfectly well and panics on the first write. The sensor
// restarts on failure, so one such panic is a crash loop, and the profile is
// touched on every cycle. Every map on Profile is guarded here, in one place,
// so adding another cannot forget.
func (p *Profile) fillMaps() {
	if p.Snapshots == nil {
		p.Snapshots = map[string]probe.Snapshot{}
	}
	if p.Accepted == nil {
		p.Accepted = map[string]Accept{}
	}
	if p.Notified == nil {
		p.Notified = map[string]time.Time{}
	}
	if p.Devices == nil {
		p.Devices = map[string]Device{}
	}
}

// SetTrust records a trust level on one stored profile.
//
// Read, modify, write - never a copy handed out by List. The sensor rewrites the
// same file every couple of minutes, so saving a listing taken seconds earlier
// silently reverts everything learned since: the device history most visibly,
// but the cooldown state and the learned snapshots with it.
func (s *Store) SetTrust(key, trust string) (*Profile, error) {
	b, err := os.ReadFile(s.file(key))
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("no profile with key %q", key)
	}
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("baseline %s: %w", key, err)
	}
	p.fillMaps()
	p.Trust = trust
	if err := s.Save(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Save writes the profile atomically: a crash mid-write must not leave a
// truncated baseline, which would read as "everything is new".
func (s *Store) Save(p *Profile) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	return s.writeFile(s.file(p.Key), b)
}

// writeFile is the atomic write both the profile and the activity log use:
// temp file, flushed, mode-restricted, then renamed over the target.
func (s *Store) writeFile(path string, b []byte) error {
	tmp, err := os.CreateTemp(s.dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op once the rename succeeds
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("baseline: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("baseline: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	return nil
}

// List returns every stored profile, newest-seen first.
func (s *Store) List() ([]*Profile, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	var out []*Profile
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		var p Profile
		if err := json.Unmarshal(b, &p); err != nil {
			continue
		}
		p.fillMaps()
		out = append(out, &p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out, nil
}

// Reset deletes a profile so the next run relearns it from scratch.
//
// The activity log beside it is deliberately kept. Relearning what is normal on
// a network is not a reason to erase the record of what has happened on it, and
// a reset that quietly destroyed that record would be the easiest way to hide
// an incident from whoever looks next.
func (s *Store) Reset(key string) error {
	err := os.Remove(s.file(key))
	if os.IsNotExist(err) {
		return fmt.Errorf("no profile %q", key)
	}
	return err
}
