// Package roots provides the embedded Mozilla CA bundle.
//
// This is the trust anchor for the whole product. It is deliberately
// independent of whatever host mitmwatch runs on: a detector that trusts the
// local system store cannot detect a root injected into that store, which is
// exactly the attack `tls/private-root` exists to catch.
package roots

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"regexp"
	"sync"
	"time"
)

//go:embed cacert.pem
var bundle []byte

var (
	once sync.Once
	pool *x509.CertPool
	n    int
	err  error
)

func load() {
	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		err = fmt.Errorf("roots: embedded bundle contains no usable certificates")
		return
	}
	rest := bundle
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			n++
		}
	}
}

// Pool returns the embedded Mozilla root pool. The returned pool is shared and
// must not be mutated.
func Pool() (*x509.CertPool, error) {
	once.Do(load)
	return pool, err
}

// Count is the number of roots in the embedded bundle.
func Count() int { once.Do(load); return n }

// SHA256 is the hex digest of the embedded bundle, for `doctor` output and for
// comparison against curl.se/ca/cacert.pem.sha256 from an uninterceptred host.
func SHA256() string {
	s := sha256.Sum256(bundle)
	return hex.EncodeToString(s[:])
}

var dateRe = regexp.MustCompile(`(?m)^## Certificate data from Mozilla as of: (.+)$`)

// BundleDate is the "as of" date Mozilla stamped on the bundle. Zero if absent.
func BundleDate() time.Time {
	m := dateRe.FindSubmatch(bundle)
	if m == nil {
		return time.Time{}
	}
	t, e := time.Parse("Mon Jan _2 15:04:05 2006 MST", string(m[1]))
	if e != nil {
		return time.Time{}
	}
	return t
}

// Certificates parses the embedded bundle into certificates, for callers that
// need to compare against it by digest rather than verify a chain with it.
func Certificates() ([]*x509.Certificate, error) {
	var (
		out  []*x509.Certificate
		rest = bundle
	)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			continue // skip anything unparseable rather than failing the set
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("roots: embedded bundle parsed to zero certificates")
	}
	return out, nil
}
