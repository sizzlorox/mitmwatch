package witness

import (
	"crypto/tls"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func newIdentity(t *testing.T, cn string) *Identity {
	t.Helper()
	id, err := LoadOrCreateIdentity(t.TempDir(), cn)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPinIsWellFormedAndStable(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreateIdentity(dir, "mitmwatch-witness")
	if err != nil {
		t.Fatal(err)
	}
	if !ValidPin(a.Pin) {
		t.Fatalf("pin %q is not well-formed", a.Pin)
	}
	// Loading again must return the same identity, not mint a new one - the pin
	// the operator copied must keep matching across restarts.
	b, err := LoadOrCreateIdentity(dir, "mitmwatch-witness")
	if err != nil {
		t.Fatal(err)
	}
	if a.Pin != b.Pin {
		t.Fatalf("pin changed on reload: %s -> %s", a.Pin, b.Pin)
	}
}

func TestValidPinRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "sha256/", "sha256/xyz", "deadbeef",
		"sha256/" + strings.Repeat("g", 64), "sha256/" + strings.Repeat("a", 63)} {
		if ValidPin(bad) {
			t.Errorf("ValidPin(%q) = true, want false", bad)
		}
	}
}

// handshake dials a server and reports whether an authenticated exchange
// actually completed.
//
// It does a full round-trip on purpose. Under TLS 1.3 the client sends its
// certificate in the last flight, so the client's own Handshake() can return
// success before the server has verified that certificate - a server-side pin
// rejection surfaces only on the next read, as the server's alert. Testing the
// pin enforcement therefore requires reading a reply, not just handshaking.
func handshake(t *testing.T, serverCfg, clientCfg *tls.Config) error {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		// Only a fully verified handshake reaches the write; a rejected client
		// cert makes Handshake return an error and the server sends an alert.
		if err := conn.(*tls.Conn).Handshake(); err != nil {
			return
		}
		conn.Write([]byte("ok")) //nolint:errcheck
	}()

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		return err
	}
	// The round-trip: read the server's reply. If the server rejected our
	// certificate, this returns an alert error or EOF instead of "ok".
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != "ok" {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// The property the whole protocol rests on: a correctly pinned pair completes
// the handshake, and a wrong pin on EITHER side fails it, before any protocol
// bytes flow.
func TestMutualPinnedHandshake(t *testing.T) {
	sensor := newIdentity(t, "mitmwatch-sensor")
	wit := newIdentity(t, "mitmwatch-witness")
	other := newIdentity(t, "mitmwatch-attacker")

	t.Run("correct pins succeed", func(t *testing.T) {
		if err := handshake(t,
			ServerTLS(wit, []string{sensor.Pin}),
			ClientTLS(sensor, wit.Pin),
		); err != nil {
			t.Fatalf("a correctly pinned pair failed to handshake: %v", err)
		}
	})

	t.Run("client with wrong witness pin is rejected", func(t *testing.T) {
		// The sensor was handed an attacker's pin as if it were the witness's.
		err := handshake(t,
			ServerTLS(wit, []string{sensor.Pin}),
			ClientTLS(sensor, other.Pin),
		)
		if err == nil {
			t.Fatal("the sensor accepted a witness whose key it had not pinned")
		}
	})

	t.Run("server rejects a client not in allow_pins", func(t *testing.T) {
		// A stranger presents a valid cert the witness was never told to trust.
		err := handshake(t,
			ServerTLS(wit, []string{sensor.Pin}), // allows only the real sensor
			ClientTLS(other, wit.Pin),            // attacker dialing in
		)
		if err == nil {
			t.Fatal("the witness accepted a client key not in allow_pins")
		}
	})

	t.Run("empty allow list rejects everyone", func(t *testing.T) {
		if err := handshake(t, ServerTLS(wit, nil), ClientTLS(sensor, wit.Pin)); err == nil {
			t.Fatal("an unconfigured witness (no allow_pins) accepted a client")
		}
	})
}

// The key must never leave the box: the on-disk key file must be owner-only.
// The witness and sensor both deploy on Linux, which is where this is enforced;
// Windows does not carry unix permission bits, so the check is skipped there
// rather than asserted falsely.
func TestKeyFileIsNotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits not meaningful on windows")
	}
	dir := t.TempDir()
	if _, err := LoadOrCreateIdentity(dir, "mitmwatch-witness"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir + "/identity.key")
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("key file mode is %o, want no group/other bits", perm)
	}
}
