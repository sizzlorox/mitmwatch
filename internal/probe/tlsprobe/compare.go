package tlsprobe

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sizzlorox/mitmwatch/internal/probe"
)

// Vectors emitted by this probe. These strings are the stable identifiers used
// by the scoring table, dedup, the accept list and (from phase 3) the
// plain-language layer, so they must not change once released.
const (
	vecSharedLeafKey = "tls/shared-leaf-key"
	vecPrivateRoot   = "tls/private-root"
	vecUntrustedRoot = "tls/untrusted-root"
	vecNoSCT         = "tls/no-sct"
	vecIssuerUnknown = "tls/issuer-unknown"
	vecCAAViolation  = "tls/caa-violation"
	vecDowngrade     = "tls/downgrade"
	vecLeafRotated   = "tls/leaf-rotated"
	vecHandshake     = "tls/handshake-failed"
	vecSysUnavail    = "tls/system-store-unavailable"
)

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

	for _, host := range sortedHosts(now.Hosts) {
		o := now.Hosts[host]

		// fired tracks which vectors this host produced, so a cross-vantage
		// corroborator can predicate on a local finding having already fired.
		fired := map[string]bool{}
		addHost := func(f probe.Finding) {
			fired[f.Vector] = true
			add(f)
		}

		if !o.ok() {
			addHost(probe.Finding{
				Vector: vecHandshake, Target: host,
				Title:    "Could not complete a secure connection to " + host,
				Evidence: map[string]string{"error": o.Err},
			})
			continue
		}

		switch {
		case o.RootInEmbedded:
			// Chains to a publicly trusted root. Nothing to say about the root.
		case o.RootInSystem == sysUnavailable:
			// D2's two-way comparison degraded to one-way. Say so rather than
			// guessing which side is at fault.
			add(probe.Finding{
				Vector: vecSysUnavail, Target: host,
				Title: "Cannot read this computer's certificate store, so the check is incomplete",
				Evidence: map[string]string{
					"root_subject": o.RootSubject,
					"reason":       firstNonEmpty(now.SystemPoolError, "system root pool unavailable"),
				},
			})
		case o.RootInSystem == sysYes:
			// The chain is trusted here and nowhere else: something on this
			// machine or this network is issuing certificates.
			f := probe.Finding{
				Vector: vecPrivateRoot, Target: host,
				Title: "A certificate authority trusted only by this computer signed " + host,
				// The root is the identity. leaf_serial is shown but not hashed:
				// an interceptor mints a fresh leaf on every rotation, and
				// hashing it would expire the accept each time.
				Identity: map[string]string{"root_subject": o.RootSubject},
				Evidence: map[string]string{
					"root_subject": o.RootSubject,
					"issuer_cn":    o.IssuerCN,
					"issuer_o":     o.IssuerO,
					"leaf_serial":  o.LeafSerial,
				},
			}
			// A managed work machine legitimately carries a private root. Once
			// it is in the baseline for a `work` profile it is expected; a
			// newly appearing one is not, and keeps full weight.
			if cc.Trust == "work" && hasBase && stableRoot(prev.Hosts[host], o) {
				f.Score = 5
				f.Title = "Managed certificate authority in use on " + host + " (expected on a work network)"
				f.Evidence["note"] = "stable across baseline; scored as information because this profile is trusted as 'work'"
			}
			addHost(f)
		default: // sysNo
			addHost(probe.Finding{
				Vector: vecUntrustedRoot, Target: host,
				Title:    "The certificate for " + host + " is signed by an authority nobody trusts",
				Identity: map[string]string{"root_subject": o.RootSubject},
				Evidence: map[string]string{
					"root_subject": o.RootSubject,
					"issuer_cn":    o.IssuerCN,
					"issuer_o":     o.IssuerO,
				},
			})
		}

		// A cross-vantage corroborator for the root finding above. Weight 5,
		// so it can only ever add confidence to an existing private/untrusted
		// root finding, never a band.
		if f, ok := witnessRootMismatch(host, o, fired, cc); ok {
			addHost(f)
		}

		// SCTs. The witness view, when it says "logged from outside but not
		// here", replaces the local no-sct for this host - checked first so the
		// loop emits one or the other, never both (which would sum 35+50 and
		// cross into Critical through the learning window).
		if wf, ok := witnessSCTUnlogged(host, o, cc); ok {
			addHost(wf)
		} else if o.SCTCount == 0 {
			addHost(probe.Finding{
				Vector: vecNoSCT, Target: host,
				Title:    "The certificate for " + host + " was never published to a public log",
				Identity: map[string]string{"issuer_cn": o.IssuerCN},
				Evidence: map[string]string{
					"sct_count":    "0",
					"issuer_cn":    o.IssuerCN,
					"ocsp_stapled": strconv.FormatBool(o.OCSPStapled),
				},
			})
		}

		if want := cc.Config.TLS.ExpectIssuers[host]; want != "" && !strings.EqualFold(want, o.IssuerO) {
			addHost(probe.Finding{
				Vector: vecIssuerUnknown, Target: host,
				Title:    "A different company issued the certificate for " + host,
				Identity: map[string]string{"observed_issuer_o": o.IssuerO},
				Evidence: map[string]string{
					"expected_issuer_o": want,
					"observed_issuer_o": o.IssuerO,
					"issuer_cn":         o.IssuerCN,
				},
			})
		}

		// CAA: the domain's own DNS statement of which CAs may issue for it. Fires
		// only when a policy exists AND the issuer maps to a known CA AND that CA
		// is not in the authorised set - every other case is silent by design.
		if o.CAAChecked && evalCAA(o.IssuerO, o.CAAAuthorized, o.CAAPresent) == caaViolation {
			addHost(probe.Finding{
				Vector: vecCAAViolation, Target: host,
				Title:    "The certificate for " + host + " is from an authority the site did not authorise",
				Identity: map[string]string{"issuer_o": o.IssuerO},
				Evidence: map[string]string{
					"issuer_o":    o.IssuerO,
					"issuer_cn":   o.IssuerCN,
					"authorised":  strings.Join(o.CAAAuthorized, ", "),
					"why":         "the site publishes in DNS which certificate authorities may issue for it; this certificate's authority is not on that list",
					"benign_case": "a site that just changed CA before updating its own CAA record can look like this briefly",
				},
			})
		}

		if o.Version == "TLS1.0" || o.Version == "TLS1.1" {
			addHost(probe.Finding{
				Vector: vecDowngrade, Target: host,
				Title:    "The connection to " + host + " used an outdated encryption version",
				Identity: map[string]string{"version": o.Version},
				Evidence: map[string]string{"version": o.Version, "cipher": o.Cipher},
			})
		}

		if p, ok := prev.Hosts[host]; hasBase && ok && p.ok() &&
			p.LeafSPKI != "" && p.LeafSPKI != o.LeafSPKI && p.IssuerO == o.IssuerO {
			// Certificate rotation is routine. It is informational on its own
			// and only matters alongside an issuer change, which is caught
			// above. See D3.
			addHost(probe.Finding{
				Vector: vecLeafRotated, Target: host,
				Title:    "The certificate for " + host + " changed, from the same issuer",
				Change:   true,
				Identity: map[string]string{"issuer_o": o.IssuerO},
				Evidence: map[string]string{
					"was_spki": short(p.LeafSPKI), "now_spki": short(o.LeafSPKI),
					"issuer_o": o.IssuerO,
				},
			})
		}
	}

	out = append(out, sharedLeafKey(now, cc)...)

	// The sensor's own link-health notice, on its own target so it never sums
	// into detection evidence.
	if f, ok := witnessUnreachable(cc); ok {
		add(f)
	}
	return out
}

// sharedLeafKey is the witness-free interception signal.
//
// Bare key sharing is NOT evidence: Cloudflare, Fastly and Akamai routinely
// serve one certificate across many unrelated hostnames, and the default pin
// list contains two Cloudflare-fronted hosts. What cannot happen legitimately
// is one key spanning hosts operated by different organisations. Two ways to
// establish that without a witness:
//
//  1. the shared chain does not reach a publicly trusted root at all, or
//  2. the configured expectations for those hosts name different issuers.
//
// From phase 2 the witness supplies a third and better answer.
func sharedLeafKey(now snapshot, cc probe.CompareCtx) []probe.Finding {
	groups := map[string][]string{}
	for _, host := range sortedHosts(now.Hosts) {
		if o := now.Hosts[host]; o.ok() && o.LeafSPKI != "" {
			groups[o.LeafSPKI] = append(groups[o.LeafSPKI], host)
		}
	}

	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []probe.Finding
	for _, spkiHash := range keys {
		hosts := groups[spkiHash]
		if len(hosts) < 2 {
			continue
		}

		privateRoot := false
		orgs := map[string]bool{}
		for _, h := range hosts {
			if !now.Hosts[h].RootInEmbedded {
				privateRoot = true
			}
			if want := cc.Config.TLS.ExpectIssuers[h]; want != "" {
				orgs[strings.ToLower(want)] = true
			}
		}
		// The witness supplies a third, and the strongest, qualifier: these
		// hosts share one key HERE but are seen on different keys from outside.
		// One real certificate has one key at every vantage, so a share that
		// exists only on the path to this sensor is a single interception key -
		// even when its chain reaches a public root, the case the two local
		// qualifiers miss.
		witnessDistinct := witnessSaysDistinct(hosts, cc)
		if !privateRoot && len(orgs) < 2 && !witnessDistinct {
			continue // a shared CDN certificate; not a finding
		}

		reason := "configured issuers for these hosts name different organisations"
		switch {
		case witnessDistinct:
			reason = "an outside vantage point sees these sites on different keys; only your network sees one shared key"
		case privateRoot:
			reason = "the shared key does not chain to a publicly trusted root"
		}
		out = append(out, probe.Finding{
			Probe: name, Vector: vecSharedLeafKey, Target: "network",
			Score: cc.Weight(vecSharedLeafKey),
			Title: fmt.Sprintf("%d unrelated websites are using the same encryption key", len(hosts)),
			// The host set and the root, not the key: the key rotates while the
			// interception continues.
			Identity: map[string]string{
				"hosts": strings.Join(hosts, ", "), "root_subject": now.Hosts[hosts[0]].RootSubject,
			},
			Evidence: map[string]string{
				"hosts":        strings.Join(hosts, ", "),
				"leaf_spki":    short(spkiHash),
				"issuer_cn":    now.Hosts[hosts[0]].IssuerCN,
				"root_subject": now.Hosts[hosts[0]].RootSubject,
				"reason":       reason,
			},
		})
	}
	return out
}

// stableRoot reports whether the same private root signed this host last time.
func stableRoot(prev, cur hostObs) bool {
	return prev.ok() && !prev.RootInEmbedded &&
		prev.RootSubject != "" && prev.RootSubject == cur.RootSubject
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
