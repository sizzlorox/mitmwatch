package tlsprobe

import (
	"context"
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/roots"
)

// The default pin list's real issuers against their real published CAA. Every
// one must be silent - this is the whole false-positive guarantee, encoded.
func TestCAAPinListIsSilent(t *testing.T) {
	cases := []struct {
		host, issuerO string
		authorized    []string
		present       bool
	}{
		// github.com: Sectigo, authorises sectigo.com among others.
		{"github.com", "Sectigo Limited",
			[]string{"digicert.com", "globalsign.com", "letsencrypt.org", "sectigo.com"}, true},
		// www.google.com: Google Trust Services; policy at google.com is pki.goog.
		{"www.google.com", "Google Trust Services", []string{"pki.goog"}, true},
		// cloudflare-dns.com: SSL Corp, authorises ssl.com.
		{"cloudflare-dns.com", "SSL Corp",
			[]string{"comodoca.com", "digicert.com", "letsencrypt.org", "pki.goog", "ssl.com"}, true},
		// registry.npmjs.org: Google Trust Services; npmjs.org authorises pki.goog.
		{"registry.npmjs.org", "Google Trust Services",
			[]string{"comodoca.com", "digicert.com", "letsencrypt.org", "pki.goog", "ssl.com"}, true},
	}
	for _, c := range cases {
		if v := evalCAA(c.issuerO, c.authorized, c.present); v != caaSilent {
			t.Errorf("%s (%s): got violation, want silent", c.host, c.issuerO)
		}
	}
}

// A real, known CA outside a policy that exists is the one case that fires.
func TestCAAViolationFires(t *testing.T) {
	// github's cert is Sectigo, but suppose the policy authorised only DigiCert.
	if v := evalCAA("Sectigo Limited", []string{"digicert.com"}, true); v != caaViolation {
		t.Fatal("a Sectigo cert against a DigiCert-only policy did not fire")
	}
}

// The conservative core: uncertainty is silence. An issuer we cannot map to a
// known CA is never a violation - the issuer-unknown rule handles that case,
// and guessing here would be a false positive.
func TestCAAUnknownIssuerIsSilent(t *testing.T) {
	if v := evalCAA("Acme Anvil Certificate Authority", []string{"digicert.com"}, true); v != caaSilent {
		t.Fatal("an unmappable issuer was judged a violation")
	}
	// No policy present -> silent regardless of issuer.
	if v := evalCAA("Sectigo Limited", nil, false); v != caaSilent {
		t.Fatal("absent CAA was judged a violation")
	}
	// Present but empty (e.g. `issue ";"`) -> no usable policy -> silent.
	if v := evalCAA("Sectigo Limited", nil, true); v != caaSilent {
		t.Fatal("an empty policy was judged a violation")
	}
}

func TestParseCAA(t *testing.T) {
	cases := []struct{ in, tag, val string }{
		{`0 issue "digicert.com; cansignhttpexchanges=yes"`, "issue", "digicert.com"},
		{`0 issuewild "letsencrypt.org"`, "issuewild", "letsencrypt.org"},
		{`0 issue "sectigo.com"`, "issue", "sectigo.com"},
		{`0 iodef "mailto:tls-abuse@cloudflare.com"`, "iodef", "mailto:tls-abuse@cloudflare.com"},
		{`0 issue ";"`, "issue", ""},
	}
	for _, c := range cases {
		tag, val := parseCAA(c.in)
		if tag != c.tag || val != c.val {
			t.Errorf("parseCAA(%q) = (%q,%q), want (%q,%q)", c.in, tag, val, c.tag, c.val)
		}
	}
}

func TestIssuerIDs(t *testing.T) {
	// Sectigo maps to both of its identifiers, so a domain authorising it under
	// either name reads as authorised.
	ids := issuerIDs("Sectigo Limited")
	if len(ids) != 2 {
		t.Fatalf("Sectigo mapped to %v, want two identifiers", ids)
	}
	if issuerIDs("Totally Unknown CA") != nil {
		t.Fatal("an unknown issuer mapped to identifiers")
	}
}

// Live: the real pin-list hosts, resolved over real DoH, must never produce a
// CAA violation. This is the network-truth backstop for the offline guarantee.
// Skipped under -short and tolerant of a DoH outage (the point is "no false
// positive", and an unreachable resolver leaves the check silent by design).
func TestCAALiveNoFalsePositive(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	pool, err := roots.Pool()
	if err != nil {
		t.Fatal(err)
	}
	const doh = "https://cloudflare-dns.com/dns-query"
	hosts := map[string]string{
		"github.com":         "Sectigo Limited",
		"www.google.com":     "Google Trust Services",
		"cloudflare-dns.com": "SSL Corp",
		"registry.npmjs.org": "Google Trust Services",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for host, issuerO := range hosts {
		auth, present, err := caaLookup(ctx, pool, doh, host)
		if err != nil {
			t.Logf("%s: DoH unreachable (%v) - skipping, absence is silent", host, err)
			continue
		}
		if v := evalCAA(issuerO, auth, present); v != caaSilent {
			t.Errorf("FALSE POSITIVE: %s (%s) present=%v authorised=%v", host, issuerO, present, auth)
		}
	}
}
