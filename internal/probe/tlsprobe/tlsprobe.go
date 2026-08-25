// Package tlsprobe detects TLS interception.
//
// The load-bearing idea is in Observe: every presented chain is verified
// twice, once against the embedded Mozilla bundle and once against the host's
// own trust store. A detector that only consults the system store cannot see a
// root injected into that store, which is precisely how local interceptors
// (ESET, mitmproxy, Burp, corporate proxies) work. The divergence between the
// two verdicts is the finding.
package tlsprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/probe"
	"github.com/sizzlorox/mitmwatch/internal/roots"
)

const name = "tls"

// System-store verdict. Tri-state on purpose: x509.SystemCertPool can fail to
// load on some Windows configurations, and a two-way comparison that silently
// degrades to one-way is worse than one that says so.
const (
	sysYes         = "yes"
	sysNo          = "no"
	sysUnavailable = "unavailable"
)

// oidSCTList is the embedded SignedCertificateTimestampList extension.
var oidSCTList = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

type hostObs struct {
	Host string `json:"host"`
	Err  string `json:"err,omitempty"`

	LeafSPKI      string    `json:"leaf_spki,omitempty"`
	LeafSerial    string    `json:"leaf_serial,omitempty"`
	LeafSubject   string    `json:"leaf_subject,omitempty"`
	LeafNotBefore time.Time `json:"leaf_not_before,omitempty"`
	LeafNotAfter  time.Time `json:"leaf_not_after,omitempty"`

	IssuerCN   string `json:"issuer_cn,omitempty"`
	IssuerO    string `json:"issuer_o,omitempty"`
	IssuerSPKI string `json:"issuer_spki,omitempty"`

	// CAA policy for this host, resolved over the embedded-root DoH channel.
	// Checked distinguishes "looked up" from "the lookup failed" so a transport
	// error never reads as "no policy". Authorized is the set of CA identifiers
	// the domain permits; empty with Present true means an unusable policy.
	CAAChecked    bool     `json:"caa_checked,omitempty"`
	CAAPresent    bool     `json:"caa_present,omitempty"`
	CAAAuthorized []string `json:"caa_authorized,omitempty"`

	RootSubject    string `json:"root_subject,omitempty"`
	RootInEmbedded bool   `json:"root_in_embedded"`
	RootInSystem   string `json:"root_in_system,omitempty"`

	ChainLen    int  `json:"chain_len,omitempty"`
	SCTCount    int  `json:"sct_count"`
	OCSPStapled bool `json:"ocsp_stapled"`

	Version string `json:"version,omitempty"`
	Cipher  string `json:"cipher,omitempty"`
	ALPN    string `json:"alpn,omitempty"`
}

func (h hostObs) ok() bool { return h.Err == "" }

type snapshot struct {
	Hosts map[string]hostObs `json:"hosts"`
	// SystemPoolError records why the system store could not be consulted.
	SystemPoolError string `json:"system_pool_error,omitempty"`
	// BundleSHA256 ties the observation to the root bundle that judged it.
	BundleSHA256 string `json:"bundle_sha256"`
}

// Probe is the tls detector.
type Probe struct{}

func init() { probe.Register(Probe{}) }

func (Probe) Name() string            { return name }
func (Probe) Interval() time.Duration { return 5 * time.Minute }

func (Probe) Observe(ctx context.Context, in probe.Inputs) (probe.Snapshot, error) {
	hosts := in.Config.TLS.Pin
	timeout := time.Duration(in.Config.TLS.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	embedded, err := roots.Pool()
	if err != nil {
		return probe.Snapshot{}, err
	}

	snap := snapshot{Hosts: make(map[string]hostObs, len(hosts)), BundleSHA256: roots.SHA256()}
	if _, err := x509.SystemCertPool(); err != nil {
		snap.SystemPoolError = err.Error()
	}

	// The CAA channel is the same trust anchor the dns probe uses: DoH verified
	// against the embedded bundle, so an on-path attacker cannot forge the policy.
	var dohEndpoint string
	if len(in.Config.DNS.DoH) > 0 {
		dohEndpoint = in.Config.DNS.DoH[0]
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for _, h := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			o := inspect(ctx, h, timeout, embedded, dohEndpoint)
			mu.Lock()
			snap.Hosts[h] = o
			mu.Unlock()
		}(h)
	}
	wg.Wait()

	return probe.Encode(name, snap)
}

// inspect performs one handshake and records everything the compare rules need.
func inspect(ctx context.Context, host string, timeout time.Duration, embedded *x509.CertPool, dohEndpoint string) hostObs {
	o := hostObs{Host: host}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			ServerName: host,
			// Deliberate: we do our own verification, twice, and must see the
			// chain even when it fails to verify. Nothing is trusted here and
			// no data is sent over this connection.
			InsecureSkipVerify: true, //nolint:gosec // inspection only, see above
			MinVersion:         tls.VersionTLS10,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		o.Err = err.Error()
		return o
	}
	defer conn.Close()

	cs := conn.(*tls.Conn).ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		o.Err = "no peer certificates"
		return o
	}
	o = observe(host, cs.PeerCertificates, connInfo{
		Version:     cs.Version,
		Cipher:      cs.CipherSuite,
		ALPN:        cs.NegotiatedProtocol,
		TLSSCTs:     len(cs.SignedCertificateTimestamps),
		OCSPStapled: len(cs.OCSPResponse) > 0,
	}, verifyEnv{Embedded: embedded})

	// CAA only matters when the handshake succeeded and we have an issuer to
	// judge. A lookup failure leaves CAAChecked false, so Compare stays silent.
	if o.ok() && dohEndpoint != "" {
		if auth, present, err := caaLookup(ctx, embedded, dohEndpoint, host); err == nil {
			o.CAAChecked, o.CAAPresent, o.CAAAuthorized = true, present, auth
		}
	}
	return o
}

// connInfo is the handshake detail that is not carried by the certificates.
type connInfo struct {
	Version     uint16
	Cipher      uint16
	ALPN        string
	TLSSCTs     int
	OCSPStapled bool
}

// verifyEnv is what the two verdicts are computed against.
//
// System is nil in production, which makes x509 use the platform verifier.
// Tests supply an explicit pool, and a fixed Now, so that a captured chain
// produces the same verdict next year as it does today.
type verifyEnv struct {
	Embedded *x509.CertPool
	System   *x509.CertPool
	Now      time.Time
}

// observe turns a presented chain into an observation. It is separate from the
// dial so that a captured chain - see testdata/chains - can be replayed through
// exactly the code that runs in production, rather than through a hand-built
// struct that only claims to match.
func observe(host string, certs []*x509.Certificate, ci connInfo, env verifyEnv) hostObs {
	o := hostObs{Host: host}
	if len(certs) == 0 {
		o.Err = "no peer certificates"
		return o
	}

	leaf := certs[0]
	o.LeafSPKI = spki(leaf)
	o.LeafSerial = strings.ToUpper(leaf.SerialNumber.Text(16))
	o.LeafSubject = leaf.Subject.String()
	o.LeafNotBefore, o.LeafNotAfter = leaf.NotBefore, leaf.NotAfter
	o.IssuerCN = leaf.Issuer.CommonName
	o.IssuerO = strings.Join(leaf.Issuer.Organization, ",")
	o.ChainLen = len(certs)
	o.Version = versionName(ci.Version)
	o.Cipher = tls.CipherSuiteName(ci.Cipher)
	o.ALPN = ci.ALPN
	o.OCSPStapled = ci.OCSPStapled
	// ponytail: SCTs from the TLS extension plus the certificate extension.
	// Stapled-OCSP SCTs are rare and would cost an OCSP parser; only presence
	// matters here, and every common interceptor emits none at all.
	o.SCTCount = ci.TLSSCTs + embeddedSCTCount(leaf)

	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
		if c.Subject.String() == leaf.Issuer.String() {
			o.IssuerSPKI = spki(c)
		}
	}

	// Verdict 1: the embedded Mozilla bundle. Independent of this host.
	if chains, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         env.Embedded,
		Intermediates: inter,
		CurrentTime:   env.Now,
	}); err == nil && len(chains) > 0 {
		o.RootInEmbedded = true
		o.RootSubject = chains[0][len(chains[0])-1].Subject.String()
	}

	// Verdict 2: this host's own trust store. Nil Roots means the platform
	// verifier on Windows and macOS.
	sysChains, sysErr := leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         env.System,
		Intermediates: inter,
		CurrentTime:   env.Now,
	})
	var rootsErr x509.SystemRootsError
	switch {
	case sysErr == nil:
		o.RootInSystem = sysYes
		if o.RootSubject == "" && len(sysChains) > 0 {
			o.RootSubject = sysChains[0][len(sysChains[0])-1].Subject.String()
		}
	case errors.As(sysErr, &rootsErr):
		o.RootInSystem = sysUnavailable
	default:
		o.RootInSystem = sysNo
	}

	if o.RootSubject == "" {
		// Neither verified: report the top of what was actually presented, so
		// the evidence still names the interceptor.
		top := certs[len(certs)-1]
		o.RootSubject = top.Issuer.String()
	}
	return o
}

func spki(c *x509.Certificate) string {
	s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(s[:])
}

// embeddedSCTCount counts entries in the certificate's SCT list extension.
//
// The count is deliberately unverified: no log ID is checked and no signature
// is validated, so it is FORGEABLE. Eighteen bytes of arbitrary data shaped
// like three entries counts as three SCTs. That is an accepted limitation, not
// an oversight, and its blast radius is bounded - an interceptor that forges
// SCTs still cannot forge the two-way verification at the core of this package,
// so tls/private-root (70) plus the root evidence still reaches Critical
// without tls/no-sct (35) contributing at all.
//
// The case it does not cover: a chain that verifies against the embedded
// Mozilla bundle, where no root finding fires and tls/no-sct is the only
// evidence. An attacker holding a genuinely trusted CA could forge the
// extension there and produce a clean result. Closing that means embedding and
// rotating CT log public keys - a real maintenance burden for a tool whose
// whole premise is one embedded bundle - so it waits for the phase 2 witness,
// which answers the same question out of band and without the key management.
//
// Measured 2026-08-25 across all five default canary hosts: every one delivers
// its SCTs embedded in the certificate, none via the handshake extension. Do
// not drop the handshake count from the sum on the strength of that - some
// servers do use it, and dropping it would manufacture false no-sct findings
// for them. See TestSCTDeliveryChannels.
func embeddedSCTCount(c *x509.Certificate) int {
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidSCTList) {
			continue
		}
		v := ext.Value
		// DER OCTET STRING wrapping the TLS-encoded list.
		if len(v) < 2 || v[0] != 0x04 {
			return 0
		}
		n := int(v[1])
		i := 2
		if n&0x80 != 0 { // long-form length
			nbytes := n & 0x7f
			if nbytes == 0 || nbytes > 2 || len(v) < 2+nbytes {
				return 0
			}
			n = 0
			for j := 0; j < nbytes; j++ {
				n = n<<8 | int(v[2+j])
			}
			i = 2 + nbytes
		}
		if i+2 > len(v) {
			return 0
		}
		list := v[i:]
		total := int(list[0])<<8 | int(list[1])
		if total > len(list)-2 {
			total = len(list) - 2
		}
		body, count := list[2:2+total], 0
		for len(body) >= 2 {
			l := int(body[0])<<8 | int(body[1])
			if l == 0 || 2+l > len(body) {
				break
			}
			count++
			body = body[2+l:]
		}
		return count
	}
	return 0
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	}
	return fmt.Sprintf("0x%04x", v)
}

// sortedHosts gives deterministic iteration for stable evidence and output.
func sortedHosts(m map[string]hostObs) []string {
	out := make([]string, 0, len(m))
	for h := range m {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
