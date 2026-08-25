package tlsprobe

import "github.com/sizzlorox/mitmwatch/internal/probe"

// Cross-vantage vectors. Every one is vantage-independent by construction: an
// honest certificate cannot produce it merely because the sensor and the
// witness sit in different regions. The rules that a different vantage CAN
// legitimately disagree about - a rotated leaf, a region-sticky issuer - are
// deliberately not scored here (see the package's design notes), because a
// single witness cannot separate honest regional variation from an attack
// without false alarms.
const (
	vecWitnessSCTUnlogged  = "tls/witness-sct-unlogged"
	vecWitnessRootMismatch = "tls/witness-root-mismatch"
	vecWitnessUnreachable  = "witness/unreachable"
)

// witnessHostView is the subset of the witness's per-host observation the
// cross-vantage rules read. It decodes from the witness's own tls snapshot,
// which is the identical type this probe produces - no second computation.
type witnessHostView struct {
	obs   hostObs
	ok    bool
	known bool
}

// witnessFor pulls the witness's observation of one host out of the view.
func witnessFor(cc probe.CompareCtx, host string) witnessHostView {
	snap, ok := cc.Witness.Snapshot(name)
	if !ok {
		return witnessHostView{}
	}
	var ws snapshot
	if decoded, err := snap.Decode(&ws); !decoded || err != nil {
		return witnessHostView{}
	}
	o, present := ws.Hosts[host]
	return witnessHostView{obs: o, ok: present && o.ok(), known: present}
}

// witnessSCTUnlogged reports whether the local host is missing SCTs that the
// witness sees present and stable.
//
// This replaces the local tls/no-sct for the host when it fires, so the caller
// must consult it BEFORE emitting no-sct. An honest CT-logged certificate
// carries its embedded SCTs to every vantage, so "present at the witness,
// absent here" is a property of the path to this sensor, not of the region. The
// OCSP-staple guard closes the one honest exception: a server that delivers its
// SCTs by stapled OCSP rather than embedding them.
func witnessSCTUnlogged(host string, local hostObs, cc probe.CompareCtx) (probe.Finding, bool) {
	if !cc.Witness.StableHost(host) {
		return probe.Finding{}, false
	}
	w := witnessFor(cc, host)
	if !w.ok {
		return probe.Finding{}, false
	}
	if w.obs.SCTCount == 0 || local.SCTCount > 0 || local.OCSPStapled {
		return probe.Finding{}, false
	}
	return probe.Finding{
		Probe: name, Vector: vecWitnessSCTUnlogged, Target: host,
		// The issuer key, not the leaf: an interceptor rotates leaves but the
		// key that signs them is the durable identity of the interception.
		Identity: map[string]string{"issuer_spki": short(local.IssuerSPKI)},
		Title:    "A secure site looks different from here than from outside",
		Evidence: map[string]string{
			"host":              host,
			"seen_here":         "no public-log proof on the certificate",
			"seen_from_outside": "public-log proof present",
			"issuer_here":       local.IssuerCN,
			"why":               "an honestly issued certificate carries its public-log proof to everyone; something between you and the internet may be substituting a different certificate",
			"what_to_do":        "avoid logging in to important sites from this network until this clears",
		},
	}, true
}

// witnessRootMismatch corroborates an EXISTING local private/untrusted-root
// finding: the witness sees this host on a normal public root, so the odd root
// is being shown to the sensor specifically.
//
// It is scored at 5 on purpose. It only ever fires when a local private-root
// (70) or untrusted-root (60) already fired, and 5 cannot tip either into
// Critical during the learning window - the summation trap that a managed
// laptop's own stable corporate root would otherwise spring. It adds confidence,
// never a band.
func witnessRootMismatch(host string, local hostObs, localVectors map[string]bool, cc probe.CompareCtx) (probe.Finding, bool) {
	if !localVectors[vecPrivateRoot] && !localVectors[vecUntrustedRoot] {
		return probe.Finding{}, false
	}
	if !cc.Witness.StableHost(host) {
		return probe.Finding{}, false
	}
	w := witnessFor(cc, host)
	if !w.ok || !w.obs.RootInEmbedded || w.obs.RootSubject == local.RootSubject {
		return probe.Finding{}, false
	}
	return probe.Finding{
		Probe: name, Vector: vecWitnessRootMismatch, Target: host,
		Identity: map[string]string{"issuer_spki": short(local.IssuerSPKI)},
		Title:    "An outside check confirms this is aimed at you",
		Evidence: map[string]string{
			"host":              host,
			"root_here":         local.RootSubject,
			"root_from_outside": w.obs.RootSubject,
			"why":               "a vantage point on another network sees this site on an ordinary public authority; only your network sees the unusual one",
		},
	}, true
}

// witnessUnreachable is the sensor's own link-health notice. It is Target
// "witness", never "network", so it can never sum with another probe's
// link-health finding into something that looks like detection. Identity is
// empty on purpose: accepting it permanently is the right thing to be able to
// do with a link notice, unlike a real detection.
func witnessUnreachable(cc probe.CompareCtx) (probe.Finding, bool) {
	if !cc.Witness.Configured || cc.Witness.Available || !cc.Witness.ReportDown {
		return probe.Finding{}, false
	}
	return probe.Finding{
		Probe: name, Vector: vecWitnessUnreachable, Target: "witness",
		Title: "Cannot reach the outside check right now",
		Evidence: map[string]string{
			"reason": firstNonEmpty(cc.Witness.Err, "the witness has not answered recently"),
			"note":   "your network is still being watched locally; only the outside comparison is paused",
		},
	}, true
}

// witnessSharedLeafKey adds the cross-vantage qualifier to the existing
// shared-leaf-key check: hosts that share one leaf key HERE but are seen on
// DIFFERENT keys from outside. One real multi-SAN certificate has one key
// everywhere, so a share that exists only on the path to this sensor is a single
// interception key spanning hosts - the case a locally trusted interceptor with
// a public root would otherwise slip past.
func witnessSaysDistinct(hosts []string, cc probe.CompareCtx) bool {
	if len(hosts) < 2 {
		return false
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		if !cc.Witness.StableHost(h) {
			return false
		}
		w := witnessFor(cc, h)
		if !w.ok || w.obs.LeafSPKI == "" {
			return false
		}
		seen[w.obs.LeafSPKI] = true
	}
	// Distinct at the witness means more than one key across these hosts.
	return len(seen) > 1
}
