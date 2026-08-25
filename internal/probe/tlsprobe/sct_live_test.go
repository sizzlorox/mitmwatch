package tlsprobe

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/config"
)

// TestSCTDeliveryChannels records where the canary hosts actually put their
// SCTs. It matters because SCTCount sums two unverified sources - the handshake
// extension and the certificate extension - and any future attempt to drop one
// of them would manufacture false tls/no-sct findings for every host that uses
// only that channel. Measure before assuming.
//
// Live network. Skipped under -short.
func TestSCTDeliveryChannels(t *testing.T) {
	if testing.Short() {
		t.Skip("live network")
	}
	for _, host := range config.Defaults().TLS.Pin {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 10 * time.Second}, "tcp", net.JoinHostPort(host, "443"),
			&tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // inspection only
		)
		if err != nil {
			t.Logf("%-22s unreachable: %v", host, err)
			continue
		}
		cs := conn.ConnectionState()
		handshake := len(cs.SignedCertificateTimestamps)
		embedded := 0
		if len(cs.PeerCertificates) > 0 {
			embedded = embeddedSCTCount(cs.PeerCertificates[0])
		}
		conn.Close()

		t.Logf("%-22s handshake=%d embedded=%d ocsp_stapled=%v", host, handshake, embedded, len(cs.OCSPResponse) > 0)
		if handshake+embedded == 0 {
			t.Errorf("%s delivered no SCTs by any channel; tls/no-sct would fire on a "+
				"legitimate host, which is a false positive", host)
		}
	}
}
