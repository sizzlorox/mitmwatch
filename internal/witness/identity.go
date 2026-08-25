package witness

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Identity is one box's long-lived keypair and self-signed certificate. There
// is no certificate authority anywhere in this protocol - trust is a pinned
// public-key digest exchanged out of band, because the whole product distrusts
// the public CA system it exists to police.
type Identity struct {
	Cert tls.Certificate
	Pin  string // sha256/<hex of SubjectPublicKeyInfo>
}

// pinPrefix marks a value as an SPKI pin, so a mistyped or truncated one is
// obviously not a pin rather than silently a different key.
const pinPrefix = "sha256/"

// SPKIPin is the pin for a parsed certificate. It hashes the
// SubjectPublicKeyInfo - the same field tlsprobe hashes - so a pin printed here
// and a leaf SPKI printed by the tls probe are the same kind of value.
func SPKIPin(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return pinPrefix + hex.EncodeToString(sum[:])
}

// LoadOrCreateIdentity returns the identity stored in dir, creating it on first
// use. The key never leaves the box; only the pin is meant to travel.
func LoadOrCreateIdentity(dir, commonName string) (*Identity, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("witness: identity dir: %w", err)
	}
	certPath := filepath.Join(dir, "identity.crt")
	keyPath := filepath.Join(dir, "identity.key")

	certPEM, cerr := os.ReadFile(certPath)
	keyPEM, kerr := os.ReadFile(keyPath)
	if cerr == nil && kerr == nil {
		return identityFromPEM(certPEM, keyPEM)
	}
	if !os.IsNotExist(cerr) && cerr != nil {
		return nil, cerr
	}

	certPEM, keyPEM, err := generate(commonName)
	if err != nil {
		return nil, err
	}
	// Write the key first and restrictively; a world-readable private key is
	// the kind of mistake that is invisible until it matters.
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("witness: write key: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("witness: write cert: %w", err)
	}
	return identityFromPEM(certPEM, keyPEM)
}

func generate(commonName string) (certPEM, keyPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	// Ten years: this is a pinned key exchanged by hand, not a web cert, so the
	// short-lifetime hygiene that CT enforces does not apply. Re-pairing to
	// rotate is a deliberate operator action.
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	return certPEM, keyPEM, nil
}

func identityFromPEM(certPEM, keyPEM []byte) (*Identity, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("witness: load keypair: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("witness: parse cert: %w", err)
	}
	cert.Leaf = leaf
	return &Identity{Cert: cert, Pin: SPKIPin(leaf)}, nil
}

// ValidPin reports whether s is a well-formed SPKI pin. A malformed pin must
// fail loudly at config time, not silently never match at handshake time.
func ValidPin(s string) bool {
	rest, ok := strings.CutPrefix(s, pinPrefix)
	if !ok || len(rest) != 64 {
		return false
	}
	_, err := hex.DecodeString(rest)
	return err == nil
}

// peerPin returns the pin of the peer's leaf certificate from a verified-raw
// handshake.
func peerPin(rawCerts [][]byte) (string, error) {
	if len(rawCerts) == 0 {
		return "", errors.New("witness: peer presented no certificate")
	}
	c, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return "", fmt.Errorf("witness: parse peer cert: %w", err)
	}
	return SPKIPin(c), nil
}

// ClientTLS is the sensor's TLS config: present our cert, and accept the server
// only if its leaf SPKI matches the pinned witness key. The public CA system is
// deliberately not consulted - InsecureSkipVerify disables it, and the pin
// check replaces it, exactly as the DoH client does for the embedded bundle.
func ClientTLS(id *Identity, witnessPin string) *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{id.Cert},
		InsecureSkipVerify: true, //nolint:gosec // replaced by the pin check below
		MinVersion:         tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			pin, err := peerPin(rawCerts)
			if err != nil {
				return err
			}
			if pin != witnessPin {
				return fmt.Errorf("witness: server key pin mismatch (got %s, pinned %s)", pin, witnessPin)
			}
			return nil
		},
	}
}

// ServerTLS is the witness's TLS config: require a client certificate and accept
// only clients whose leaf SPKI is in the allow set. An unpinned client is
// dropped at the handshake, before it can send a single byte of protocol.
func ServerTLS(id *Identity, allow []string) *tls.Config {
	allowed := make(map[string]bool, len(allow))
	for _, p := range allow {
		allowed[p] = true
	}
	return &tls.Config{
		Certificates: []tls.Certificate{id.Cert},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			pin, err := peerPin(rawCerts)
			if err != nil {
				return err
			}
			if !allowed[pin] {
				return fmt.Errorf("witness: client key %s is not in allow_pins", pin)
			}
			return nil
		},
	}
}
