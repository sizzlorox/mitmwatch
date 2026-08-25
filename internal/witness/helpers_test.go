package witness

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/config"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

// mustListen binds a pinned-mTLS listener on an ephemeral port for tests.
func mustListen(t *testing.T, witID *Identity, cfg *config.Config) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return tls.NewListener(ln, ServerTLS(witID, cfg.Witness.AllowPins))
}

// tlsSnapFor builds a witness tls snapshot for a set of hosts, all with the
// same fields - the shape the real probe emits, so stability decode is real.
func tlsSnapFor(t *testing.T, hosts []string, issuerO, issuerSPKI, root string, embedded bool, sct int, leaf string) probe.Snapshot {
	t.Helper()
	h := map[string]any{}
	for _, host := range hosts {
		h[host] = map[string]any{
			"host": host, "issuer_o": issuerO, "issuer_spki": issuerSPKI,
			"root_subject": root, "root_in_embedded": embedded, "sct_count": sct,
			"leaf_spki": leaf, "version": "TLS1.3",
		}
	}
	b, err := json.Marshal(map[string]any{"hosts": h, "bundle_sha256": "x"})
	if err != nil {
		t.Fatal(err)
	}
	return probe.Snapshot{Probe: "tls", Time: time.Now(), Data: b}
}
