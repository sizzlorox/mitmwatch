package roots

import (
	"strings"
	"testing"
	"time"
)

func TestBundleLoads(t *testing.T) {
	p, err := Pool()
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("nil pool")
	}
	// A bundle that silently shrinks would weaken every verdict in the
	// product, so hold a floor rather than an exact count.
	if n := Count(); n < 100 {
		t.Errorf("embedded bundle holds %d roots, want at least 100", n)
	}
	if len(SHA256()) != 64 {
		t.Errorf("digest %q is not a sha256 hex string", SHA256())
	}
}

func TestBundleIsCurrent(t *testing.T) {
	d := BundleDate()
	if d.IsZero() {
		t.Fatal("bundle carries no Mozilla date stamp")
	}
	if age := time.Since(d); age > 400*24*time.Hour {
		t.Errorf("embedded bundle is %.0f days old; run `make roots`", age.Hours()/24)
	}
}

// The whole design rests on the embedded bundle being independent of this
// host. If a locally injected root ever got in, every detector built on it
// would go blind at once.
func TestBundleHoldsNoLocalInterceptor(t *testing.T) {
	certs, err := Certificates()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range certs {
		for _, bad := range []string{"ESET", "Fiddler", "mitmproxy", "Burp", "Charles Proxy"} {
			if strings.Contains(c.Subject.String(), bad) {
				t.Errorf("embedded bundle contains %q: %s", bad, c.Subject)
			}
		}
	}
}
