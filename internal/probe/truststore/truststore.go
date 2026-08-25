// Package truststore watches the certificate authorities this machine trusts.
//
// This probe exists because of a gap the canary probes cannot close. Real
// interceptors filter selectively: ESET's SSL filter, measured on the machine
// this was written on, rewrites certificates for .NET and browser processes
// while leaving an unrecognised binary alone. A sensor that only inspects its
// own handshakes therefore sees a clean network while the user's browser is
// being read. No capture tier, vantage point or witness can detect that - the
// interception never touches the sensor's traffic. Enumerating the trust store
// can, because the injected root has to be there for the attack to work at all.
//
// Phase 0 ships the probe only. The agent that carries it to other hosts, and
// the proxy/hosts/ssh probes beside it, remain phase 3.
package truststore

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/probe"
	"github.com/sizzlorox/mitmwatch/internal/roots"
)

const name = "truststore"

// maxAge is how recently a root must have been issued to count as young.
//
// Measured on a working Windows 11 install: 68 distinct roots, 38 absent from
// Mozilla's bundle, 37 of those usable for server authentication - so bare
// set-difference is useless as an alarm. Adding "issued within maxAge" cuts
// that to exactly the three roots a human or an application installed locally.
// Public CAs do mint new roots, but they reach the Mozilla bundle, so they
// leave this set by the other condition.
//
// The 37 counts EKUs as the certificate itself declares them. Windows also
// keeps a per-store EKU property that restricts many of its shipped roots
// further - counting that way gives 27. Reading the certificate is the
// portable answer and the conservative one; the extra ten are all pre-2018
// Microsoft roots that maxAge removes regardless.
const maxAge = 400 * 24 * time.Hour

// rawRoot is one certificate as the platform handed it over.
type rawRoot struct {
	DER   []byte
	Store string
}

type rootObs struct {
	Subject    string    `json:"subject"`
	CN         string    `json:"cn,omitempty"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	ServerAuth bool      `json:"server_auth"`
	InMozilla  bool      `json:"in_mozilla"`
	SelfSigned bool      `json:"self_signed"`
	Stores     []string  `json:"stores"`
}

// Name is the CN when there is one, else the full subject. Used as the alert
// target so each root is independently acceptable.
func (r rootObs) Name() string {
	if r.CN != "" {
		return r.CN
	}
	return r.Subject
}

type snapshot struct {
	// Roots is keyed by the SHA-256 of the certificate's DER encoding.
	Roots map[string]rootObs `json:"roots"`
	Total int                `json:"total"`
	// NotInMozilla and ServerAuthExtra are kept for doctor and for judging
	// whether the thresholds still make sense on a given platform.
	NotInMozilla    int    `json:"not_in_mozilla"`
	ServerAuthExtra int    `json:"server_auth_extra"`
	Err             string `json:"err,omitempty"`
}

type Probe struct{}

func init() { probe.Register(Probe{}) }

func (Probe) Name() string { return name }

// Interval is short relative to the canaries: an injected root is the highest
// scoring single piece of evidence in the product and costs nothing to check.
func (Probe) Interval() time.Duration { return 2 * time.Minute }

func (Probe) Observe(ctx context.Context, _ probe.Inputs) (probe.Snapshot, error) {
	snap := snapshot{Roots: map[string]rootObs{}}

	raws, err := systemRoots(ctx)
	if err != nil && len(raws) == 0 {
		snap.Err = err.Error()
		return probe.Incomplete(name, snap, err)
	}

	moz, err := mozillaDigests()
	if err != nil {
		return probe.Snapshot{}, err
	}

	for _, r := range raws {
		c, err := x509.ParseCertificate(r.DER)
		if err != nil {
			continue // a store can hold entries that are not certificates
		}
		sum := sha256.Sum256(r.DER)
		key := hex.EncodeToString(sum[:])

		o, seen := snap.Roots[key]
		if !seen {
			o = rootObs{
				Subject:    c.Subject.String(),
				CN:         c.Subject.CommonName,
				NotBefore:  c.NotBefore,
				NotAfter:   c.NotAfter,
				ServerAuth: serverAuth(c),
				InMozilla:  moz[key],
				SelfSigned: c.Subject.String() == c.Issuer.String(),
			}
			snap.Total++
			if !o.InMozilla {
				snap.NotInMozilla++
				if o.ServerAuth {
					snap.ServerAuthExtra++
				}
			}
		}
		if !contains(o.Stores, r.Store) {
			o.Stores = append(o.Stores, r.Store)
			sort.Strings(o.Stores)
		}
		snap.Roots[key] = o
	}
	// A partial read is more dangerous than a total one: it looks like a
	// complete answer with some roots missing, so adopting it would report
	// every missing root as newly added on the next healthy pass.
	if err != nil {
		snap.Err = err.Error()
		return probe.Incomplete(name, snap, err)
	}
	return probe.Encode(name, snap)
}

// serverAuth reports whether this root can vouch for a TLS server. A root with
// no EKU extension is unrestricted, so it counts. Windows ships a long tail of
// code-signing and timestamping roots that this filters out.
func serverAuth(c *x509.Certificate) bool {
	if len(c.ExtKeyUsage) == 0 && len(c.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

// mozillaDigests is the embedded bundle keyed the same way as the observations.
func mozillaDigests() (map[string]bool, error) {
	certs, err := roots.Certificates()
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(certs))
	for _, c := range certs {
		sum := sha256.Sum256(c.Raw)
		out[hex.EncodeToString(sum[:])] = true
	}
	return out, nil
}

const (
	vecRootAdded  = "truststore/root-added"
	vecYoungRoot  = "truststore/young-root"
	vecUnreadable = "truststore/unreadable"
)

// Summary reports the store counts for `doctor`. Surfacing them is how you
// confirm on each new platform that the maxAge threshold is still doing the
// work it does on Windows (38 candidates down to 3) rather than quietly
// collapsing to nothing - on Linux the system store often *is* Mozilla's set,
// so a zero here means something different than it does on Windows.
type Summary struct {
	Total           int
	NotInMozilla    int
	ServerAuthExtra int
	Err             string
}

// Summarize reads a stored snapshot. It reports false when there is none yet.
func Summarize(s probe.Snapshot) (Summary, bool) {
	var snap snapshot
	ok, err := s.Decode(&snap)
	if !ok || err != nil {
		return Summary{}, false
	}
	return Summary{
		Total:           snap.Total,
		NotInMozilla:    snap.NotInMozilla,
		ServerAuthExtra: snap.ServerAuthExtra,
		Err:             snap.Err,
	}, true
}

func (Probe) Compare(base, cur probe.Snapshot, cc probe.CompareCtx) []probe.Finding {
	var now snapshot
	if ok, err := cur.Decode(&now); !ok || err != nil {
		return nil
	}
	var prev snapshot
	hasBase, _ := base.Decode(&prev)

	var out []probe.Finding
	add := func(f probe.Finding) {
		f.Probe = name
		if f.Score == 0 {
			f.Score = cc.Weight(f.Vector)
		}
		out = append(out, f)
	}

	// A store that could not be read produces an empty root set, which would
	// otherwise be indistinguishable from a clean one. On the Pi - the
	// designated clean baseline - silence is the expected output, so silence
	// has to mean "looked and found nothing", never "did not look".
	if now.Err != "" {
		add(probe.Finding{
			Vector: vecUnreadable, Target: "this computer",
			Title: "Could not read the list of certificate authorities this computer trusts",
			Evidence: map[string]string{
				"error": now.Err,
				"note":  "the strongest check in the product did not run",
			},
		})
		return out
	}

	keys := make([]string, 0, len(now.Roots))
	for k := range now.Roots {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		r := now.Roots[k]
		// A root that is in Mozilla's bundle is a public CA doing its job, and
		// one that cannot vouch for a server cannot be used to intercept TLS.
		// Neither is evidence.
		if r.InMozilla || !r.ServerAuth {
			continue
		}

		ev := map[string]string{
			"subject":     r.Subject,
			"stores":      strings.Join(r.Stores, ", "),
			"issued":      r.NotBefore.Format("2006-01-02"),
			"expires":     r.NotAfter.Format("2006-01-02"),
			"self_signed": strconv.FormatBool(r.SelfSigned),
			"sha256":      short(k),
		}

		if hasBase {
			if _, existed := prev.Roots[k]; !existed {
				add(probe.Finding{
					Vector: vecRootAdded, Target: r.Name(),
					Title: "A new certificate authority was installed on this computer",
					// A root appearing is a change: the baseline must not absorb
					// it, or tomorrow it is merely a root that was always there.
					Change:   true,
					Identity: map[string]string{"sha256": k},
					Evidence: ev,
				})
				continue
			}
			// Present before and still present: already reported, or accepted.
		}

		if time.Since(r.NotBefore) < maxAge {
			ev["age_days"] = strconv.Itoa(int(time.Since(r.NotBefore).Hours() / 24))
			ev["why"] = "it can vouch for any website, it is not one of the authorities browsers ship with, and it was created recently"
			add(probe.Finding{
				Vector: vecYoungRoot, Target: r.Name(),
				Title: "A recently created certificate authority is trusted by this computer",
				// The certificate's digest, never its age. Accepting this root
				// must not expire at midnight when age_days ticks over.
				Identity: map[string]string{"sha256": k},
				Evidence: ev,
			})
		}
	}
	return out
}

// short truncates a digest for display without assuming its length: a probe
// must never panic, whatever a platform hands it.
func short(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
