package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// Event is one entry in the activity log: an alert raised or cleared, a finding
// held back, a check that stopped running, the sensor starting.
//
// It carries the evidence, not just the headline. An alert that has since
// cleared is the case that matters: the card goes green, the alert card
// disappears, and all that is left is a line saying something was found. A line
// that cannot say which device it was about, or what was actually seen, is a
// record of an event rather than a record of what happened.
type Event struct {
	When time.Time `json:"when"`
	// Kind is one of: alert, clear, stale, held, system.
	Kind string `json:"kind"`
	Text string `json:"text"`
	// Target is what the alert was about - an address, a hostname, "network".
	Target string `json:"target,omitempty"`
	// Device is the human label for Target at the time it happened, resolved
	// from the device history. Stored rather than resolved on read, because by
	// the time anyone looks the lease may have moved.
	Device string `json:"device,omitempty"`
	Band   string `json:"band,omitempty"`
	// Vectors and Hashes list every finding that contributed, not just the
	// first: two probes agreeing on one target is the interesting case, and the
	// hash is what `baseline accept` takes.
	Vectors  []string          `json:"vectors,omitempty"`
	Hashes   []string          `json:"hashes,omitempty"`
	Evidence map[string]string `json:"evidence,omitempty"`
}

// MaxEvents is how much of the log is kept on disk. Bounded because the file is
// rewritten whenever it changes and every entry carries an evidence map.
const MaxEvents = 200

// Bounds on one stored event. Evidence is text a host on the network chose, so
// it is capped here, in the store, rather than trusted to be reasonable.
const (
	maxEventText     = 512
	maxEventEvidence = 12
	maxEvidenceValue = 400
)

func (s *Store) eventsFile(key string) string { return s.file(key) + ".events.json" }

// LoadEvents returns the stored activity log, oldest first. A missing file is
// not an error: it is a sensor that has not recorded anything yet.
func (s *Store) LoadEvents(key string) ([]Event, error) {
	b, err := os.ReadFile(s.eventsFile(key))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("baseline events: %w", err)
	}
	var evs []Event
	if err := json.Unmarshal(b, &evs); err != nil {
		// A corrupt log is worth reporting, but it must not stop the sensor
		// from starting - the log is a convenience, the detection is not.
		return nil, fmt.Errorf("baseline events %s: %w", key, err)
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].When.Before(evs[j].When) })
	return evs, nil
}

// SaveEvents writes the newest MaxEvents entries, atomically.
//
// It lives beside the profile rather than inside it for two reasons. The
// profile is rewritten every cycle whether or not anything happened, and an
// evidence map is larger than the rest of that file put together; and `baseline
// reset` deletes the profile to relearn a network, which must not also delete
// the record of what happened on it.
func (s *Store) SaveEvents(key string, evs []Event) error {
	if len(evs) > MaxEvents {
		evs = evs[len(evs)-MaxEvents:]
	}
	out := make([]Event, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.bounded())
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("baseline events: %w", err)
	}
	return s.writeFile(s.eventsFile(key), b)
}

// bounded returns a copy with every attacker-influenced field capped.
func (e Event) bounded() Event {
	e.Text = truncate(e.Text, maxEventText)
	if len(e.Evidence) == 0 {
		e.Evidence = nil
		return e
	}
	keys := make([]string, 0, len(e.Evidence))
	for k := range e.Evidence {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > maxEventEvidence {
		keys = keys[:maxEventEvidence]
	}
	ev := make(map[string]string, len(keys))
	for _, k := range keys {
		ev[k] = truncate(e.Evidence[k], maxEvidenceValue)
	}
	e.Evidence = ev
	return e
}
