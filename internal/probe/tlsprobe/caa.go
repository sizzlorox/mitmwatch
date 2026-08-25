package tlsprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// CAA (RFC 8659) is the domain owner's own statement of which CAs may issue for
// it, published in DNS. It catches a case the embedded-root check cannot: a cert
// from a genuine, publicly-trusted CA that the domain never authorised - a CA
// misissuance or compromise, where the chain is real and the SCTs are present,
// but the issuer is not one the owner permits.
//
// It is deliberately conservative, because CAA is a minefield of false
// positives if taken naively:
//
//   - Most domains publish no CAA at all; absence means "any CA may issue", not
//     a violation. No record anywhere in the tree -> silent.
//   - The record lives at the zone apex, not the leaf: registry.npmjs.org has
//     none, npmjs.org has it. The lookup must climb the tree or it will read a
//     real policy as absent.
//   - The record names a CA by an identifier domain (pki.goog), the certificate
//     names it by an organisation (Google Trust Services). Only a CA whose
//     identity maps, with confidence, to a known CA identifier is judged; an
//     issuer we cannot map is left to the issuer-unknown rule, never guessed
//     here. Uncertainty is silence, so the only way to fire is a known CA that
//     is definitively outside a policy that definitely exists.
type caaVerdict int

const (
	caaSilent    caaVerdict = iota // no policy, unmappable issuer, or authorised
	caaViolation                   // a known CA, outside a policy that exists
)

// caIdentifiers maps a fragment of a certificate issuer's organisation name to
// every CAA identifier that operator publishes under. Listing all of an
// operator's identifiers is what makes a positive safe: authorisation holds if
// ANY of them appears, so a domain that authorises Sectigo as "comodoca.com"
// does not read as a violation for a "Sectigo Limited" cert.
//
// Ground-truthed against the real issuer organisations of the default pin list
// (Sectigo, Google Trust Services, SSL Corp, DigiCert) and their published CAA.
var caIdentifiers = []struct {
	issuerFragment string
	ids            []string
}{
	{"sectigo", []string{"sectigo.com", "comodoca.com"}},
	{"comodo", []string{"sectigo.com", "comodoca.com"}},
	{"google trust", []string{"pki.goog", "google.com"}},
	{"digicert", []string{"digicert.com"}},
	{"let's encrypt", []string{"letsencrypt.org"}},
	{"lets encrypt", []string{"letsencrypt.org"}},
	{"ssl corp", []string{"ssl.com"}},
	{"ssl.com", []string{"ssl.com"}},
	{"globalsign", []string{"globalsign.com"}},
	{"amazon", []string{"amazon.com", "amazontrust.com", "awstrust.com"}},
	{"microsoft", []string{"microsoft.com"}},
	{"entrust", []string{"entrust.net"}},
	{"godaddy", []string{"godaddy.com"}},
	{"starfield", []string{"starfieldtech.com", "godaddy.com"}},
	{"certum", []string{"certum.pl", "certum.eu"}},
	{"asseco", []string{"certum.pl", "certum.eu"}},
	{"buypass", []string{"buypass.com", "buypass.no"}},
	{"actalis", []string{"actalis.it"}},
}

// issuerIDs returns the CAA identifiers for a certificate issuer organisation,
// or nil when the issuer maps to no known operator - in which case CAA stays
// silent and the issuer-unknown rule, not this one, is what may speak.
func issuerIDs(issuerO string) []string {
	o := strings.ToLower(issuerO)
	for _, e := range caIdentifiers {
		if strings.Contains(o, e.issuerFragment) {
			return e.ids
		}
	}
	return nil
}

// evalCAA is the whole decision, pure and testable apart from any network. It
// returns caaViolation only when a policy exists AND the issuer is a known CA
// AND none of that CA's identifiers is authorised.
func evalCAA(issuerO string, authorized []string, present bool) caaVerdict {
	if !present || len(authorized) == 0 {
		return caaSilent // no usable policy: any CA may issue
	}
	ids := issuerIDs(issuerO)
	if len(ids) == 0 {
		return caaSilent // unmappable issuer: do not guess
	}
	auth := make(map[string]bool, len(authorized))
	for _, a := range authorized {
		auth[a] = true
	}
	for _, id := range ids {
		if auth[id] {
			return caaSilent // this CA is authorised
		}
	}
	return caaViolation
}

// caaLookup resolves the CAA policy for a host over an embedded-root DoH channel,
// climbing from the leaf to the apex. present is false when the tree carries no
// CAA at all. A transport error is returned so the caller records "not checked"
// rather than "no policy" - the two must never be conflated.
func caaLookup(ctx context.Context, pool *x509.CertPool, endpoint, host string) (authorized []string, present bool, err error) {
	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			Proxy:           nil, // never route the comparison channel through a proxy
		},
	}
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	// Climb leaf -> apex, stopping at a two-label floor so a public suffix is
	// never queried. First node with any CAA record wins (that is the policy
	// that applies); a node with none means keep climbing.
	for i := 0; i+2 <= len(labels); i++ {
		name := strings.Join(labels[i:], ".")
		ids, found, e := caaQuery(ctx, client, endpoint, name)
		if e != nil {
			return nil, false, e
		}
		if found {
			return ids, true, nil
		}
	}
	return nil, false, nil
}

type dnsJSON struct {
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// caaQuery asks one node for CAA. found reports whether the node carries any CAA
// record (type 257) at all; ids are the non-empty issue/issuewild identifiers.
func caaQuery(ctx context.Context, c *http.Client, endpoint, name string) (ids []string, found bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?name="+name+"&type=CAA", nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, &httpStatus{resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, false, err
	}
	var j dnsJSON
	if err := json.Unmarshal(body, &j); err != nil {
		return nil, false, err
	}
	seen := map[string]bool{}
	for _, a := range j.Answer {
		if a.Type != 257 { // CAA
			continue
		}
		found = true
		// issue and issuewild routinely name the same CA; collect each identifier
		// once so the stored evidence reads cleanly.
		if tag, val := parseCAA(a.Data); tag == "issue" || tag == "issuewild" {
			if val != "" && !seen[val] {
				seen[val] = true
				ids = append(ids, val)
			}
		}
	}
	return ids, found, nil
}

// parseCAA pulls the tag and the CA identifier out of one record's presentation
// form, e.g. `0 issue "digicert.com; cansignhttpexchanges=yes"` -> issue,
// digicert.com. The parameters after ';' and the surrounding quotes are stripped.
func parseCAA(data string) (tag, value string) {
	f := strings.Fields(data)
	if len(f) < 3 {
		return "", ""
	}
	tag = strings.ToLower(f[1])
	rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(data[strings.Index(data, f[1])+len(f[1]):]), " "))
	rest = strings.Trim(rest, `"`)
	if i := strings.IndexByte(rest, ';'); i >= 0 {
		rest = rest[:i]
	}
	return tag, strings.ToLower(strings.TrimSpace(rest))
}

type httpStatus struct{ code int }

func (e *httpStatus) Error() string { return "http " + itoa(e.code) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
