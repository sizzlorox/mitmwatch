package witness

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// History records the witness's OWN vantage over time, so a rule can ask "has
// this host consistently carried public-log proof from here?" before trusting a
// cross-vantage difference. It records only what the witness observed itself,
// never anything the sensor reported: a sensor that is already intercepted must
// not be able to teach the witness that its attacker is normal.
type History struct {
	path string

	mu   sync.Mutex
	recs map[string]*HostRec
	obs  int
}

// HostRec is the accumulated witness view of one host.
type HostRec struct {
	IssuerOrgs map[string]Seen `json:"issuer_orgs,omitempty"`
	IssuerKeys map[string]Seen `json:"issuer_keys,omitempty"`
	Roots      map[string]Seen `json:"roots,omitempty"`
	// SCTAlways is true while every observation of this host has carried SCTs.
	// One observation without them turns it false permanently, which is the
	// conservative direction: we stop trusting "the witness always sees SCTs"
	// the moment that stops being true.
	SCTAlways bool `json:"sct_always"`
	Obs       int  `json:"obs"`
}

// Seen is when a value was first and last observed, and how often.
type Seen struct {
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
	Count int       `json:"count"`
}

// sctFloor is how many times the witness must have seen a host before its
// "always had SCTs" record is trusted as a guard. Below it, a brand-new witness
// has not observed enough to vouch.
const sctFloor = 3

// LoadHistory reads the store, tolerating a missing or corrupt file: a witness
// that cannot read its history must still serve, just without the extra guard.
func LoadHistory(path string) *History {
	h := &History{path: path, recs: map[string]*HostRec{}}
	b, err := os.ReadFile(path)
	if err != nil {
		return h
	}
	var on disk
	if json.Unmarshal(b, &on) == nil {
		if on.Recs != nil {
			h.recs = on.Recs
		}
		h.obs = on.Obs
	}
	return h
}

type disk struct {
	Recs map[string]*HostRec `json:"recs"`
	Obs  int                 `json:"obs"`
}

// WitnessTLS is the minimal per-host fact History records, extracted by the
// server from its own tls observation.
type WitnessTLS struct {
	IssuerO     string
	IssuerSPKI  string
	RootSubject string
	HasSCT      bool
}

// Record folds one observation of a host into the store.
func (h *History) Record(host string, o WitnessTLS) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.recs[host]
	if r == nil {
		r = &HostRec{
			IssuerOrgs: map[string]Seen{}, IssuerKeys: map[string]Seen{}, Roots: map[string]Seen{},
			SCTAlways: true,
		}
		h.recs[host] = r
	}
	now := time.Now().UTC()
	bump(r.IssuerOrgs, o.IssuerO, now)
	bump(r.IssuerKeys, o.IssuerSPKI, now)
	bump(r.Roots, o.RootSubject, now)
	if !o.HasSCT {
		r.SCTAlways = false
	}
	r.Obs++
	h.obs++
}

func bump(m map[string]Seen, key string, now time.Time) {
	if key == "" {
		return
	}
	s, ok := m[key]
	if !ok {
		s.First = now
	}
	s.Last = now
	s.Count++
	m[key] = s
}

// SCTStable reports whether the witness has seen this host enough times and has
// always seen SCTs on it. This is the second guard on witness-sct-unlogged.
func (h *History) SCTStable(host string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.recs[host]
	return r != nil && r.Obs >= sctFloor && r.SCTAlways
}

// Snapshot returns a copy of the records for the audit CLI.
func (h *History) Snapshot() map[string]HostRec {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]HostRec, len(h.recs))
	for k, v := range h.recs {
		out[k] = *v
	}
	return out
}

// Save writes the store atomically. A crash mid-write must not corrupt what the
// SCT guard depends on.
func (h *History) Save() error {
	h.mu.Lock()
	on := disk{Recs: h.recs, Obs: h.obs}
	h.mu.Unlock()

	b, err := json.MarshalIndent(on, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(h.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".hist-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, h.path)
}
