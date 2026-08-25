package tlsprobe

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/probe"
	"github.com/sizzlorox/mitmwatch/internal/roots"
)

// These tests replay real captured chains through observe(), the same function
// the live dial calls. Everything else in this package's tests builds hostObs
// by hand, which validates Compare but never the extraction and the two-way
// verification underneath it.
//
//	eset.pem  - github.com as presented by ESET's SSL filter on the machine
//	            this was developed on. Captured from PowerShell, which ESET
//	            does filter; it does not filter an unrecognised Go binary.
//	clean.pem - the genuine github.com chain, for the negative case.

func loadChain(t *testing.T, name string) []*x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "chains", name))
	if err != nil {
		t.Fatalf("missing fixture %s: %v", name, err)
	}
	var certs []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		t.Fatalf("%s contained no certificates", name)
	}
	return certs
}

func embeddedPool(t *testing.T) *x509.CertPool {
	t.Helper()
	p, err := roots.Pool()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// poolOf makes the leaf's own chain trusted, which is what an injected root in
// the system store amounts to.
func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

// validAt pins verification to a moment inside the leaf's validity window, so
// the fixture does not start failing when the captured certificate expires.
func validAt(certs []*x509.Certificate) time.Time {
	return certs[0].NotBefore.Add(time.Hour)
}

func TestObserveRealInterceptedChain(t *testing.T) {
	certs := loadChain(t, "eset.pem")
	root := certs[len(certs)-1]

	o := observe("github.com", certs,
		connInfo{Version: tls.VersionTLS13, Cipher: tls.TLS_AES_128_GCM_SHA256},
		verifyEnv{Embedded: embeddedPool(t), System: poolOf(root), Now: validAt(certs)})

	if o.Err != "" {
		t.Fatalf("observe failed: %s", o.Err)
	}
	if o.RootInEmbedded {
		t.Error("an interceptor's root verified against the embedded Mozilla bundle")
	}
	if o.RootInSystem != sysYes {
		t.Errorf("RootInSystem = %q, want %q - the fixture puts the root in the store", o.RootInSystem, sysYes)
	}
	if o.SCTCount != 0 {
		t.Errorf("SCTCount = %d, want 0 - interceptors do not log their certificates", o.SCTCount)
	}
	if o.IssuerCN != "ESET SSL Filter CA" {
		t.Errorf("IssuerCN = %q, want the interceptor's name in the evidence", o.IssuerCN)
	}
	if o.LeafSPKI == "" || len(o.LeafSPKI) != 64 {
		t.Errorf("LeafSPKI = %q, want a sha256 hex digest", o.LeafSPKI)
	}

	// End to end: the observation must reach critical through Compare.
	snapshot, err := probe.Encode(name, snapshot{Hosts: map[string]hostObs{"github.com": o}})
	if err != nil {
		t.Fatal(err)
	}
	got := vectors((Probe{}).Compare(probe.Snapshot{}, snapshot, ctx(t, "unknown")))
	total := 0
	for _, s := range got {
		total += s
	}
	if _, ok := got[vecPrivateRoot]; !ok {
		t.Errorf("missing %s; got %v", vecPrivateRoot, got)
	}
	if _, ok := got[vecNoSCT]; !ok {
		t.Errorf("missing %s; got %v", vecNoSCT, got)
	}
	if total < 80 {
		t.Errorf("a real interception scored %d, want >= 80 (critical): %v", total, got)
	}
}

// The same real chain served for two different hosts is the shared-key signal,
// exercised here on interceptor data rather than a synthetic struct.
func TestSharedLeafKeyOnRealInterceptedChain(t *testing.T) {
	certs := loadChain(t, "eset.pem")
	env := verifyEnv{Embedded: embeddedPool(t), System: poolOf(certs[len(certs)-1]), Now: validAt(certs)}

	a := observe("github.com", certs, connInfo{Version: tls.VersionTLS13}, env)
	b := observe("www.google.com", certs, connInfo{Version: tls.VersionTLS13}, env)
	if a.LeafSPKI != b.LeafSPKI {
		t.Fatal("fixture setup is wrong: the two observations should share a key")
	}

	s, err := probe.Encode(name, snapshot{Hosts: map[string]hostObs{"github.com": a, "www.google.com": b}})
	if err != nil {
		t.Fatal(err)
	}
	got := vectors((Probe{}).Compare(probe.Snapshot{}, s, ctx(t, "unknown")))
	if got[vecSharedLeafKey] < 60 {
		t.Fatalf("%s scored %d on a real interceptor, want >= 60: %v",
			vecSharedLeafKey, got[vecSharedLeafKey], got)
	}
}

// The negative that keeps the positives honest: the genuine chain for the same
// host must verify against the embedded bundle and produce nothing.
func TestObserveRealCleanChain(t *testing.T) {
	certs := loadChain(t, "clean.pem")
	pool := embeddedPool(t)

	o := observe("github.com", certs,
		connInfo{Version: tls.VersionTLS13, Cipher: tls.TLS_AES_128_GCM_SHA256, TLSSCTs: 0},
		verifyEnv{Embedded: pool, System: pool, Now: validAt(certs)})

	if o.Err != "" {
		t.Fatalf("observe failed: %s", o.Err)
	}
	if !o.RootInEmbedded {
		t.Fatalf("the genuine github.com chain did not verify against the embedded bundle "+
			"(root reported as %q) - the bundle or the verification is wrong", o.RootSubject)
	}
	if o.SCTCount == 0 {
		t.Errorf("a publicly issued certificate carried no SCTs; embeddedSCTCount may be broken")
	}
	if o.IssuerO == "" {
		t.Error("issuer organisation is empty; the shared-key guard depends on it")
	}

	s, err := probe.Encode(name, snapshot{Hosts: map[string]hostObs{"github.com": o}})
	if err != nil {
		t.Fatal(err)
	}
	if got := vectors((Probe{}).Compare(probe.Snapshot{}, s, ctx(t, "unknown"))); len(got) != 0 {
		t.Fatalf("the genuine chain produced findings: %v", got)
	}
}

// embeddedSCTCount walks attacker-supplied DER. It must never panic and must
// never invent a count.
func TestEmbeddedSCTCountOnMalformedInput(t *testing.T) {
	certs := loadChain(t, "clean.pem")
	real := embeddedSCTCount(certs[0])
	if real == 0 {
		t.Skip("fixture leaf carries no embedded SCT extension")
	}
	for _, ext := range certs[0].Extensions {
		if !ext.Id.Equal(oidSCTList) {
			continue
		}
		for cut := 0; cut < len(ext.Value); cut++ {
			truncated := certs[0]
			c := *truncated
			c.Extensions = []pkix.Extension{{Id: ext.Id, Value: ext.Value[:cut]}}
			if n := embeddedSCTCount(&c); n > real {
				t.Fatalf("truncating to %d bytes produced %d SCTs, more than the intact %d",
					cut, n, real)
			}
		}
	}
}
