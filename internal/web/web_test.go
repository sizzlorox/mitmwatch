package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sizzlorox/mitmwatch/internal/core/verdict"
	"github.com/sizzlorox/mitmwatch/internal/probe"
)

func get(t *testing.T, h http.Handler, path string) (int, string, http.Header) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	b, _ := io.ReadAll(w.Result().Body)
	return w.Code, string(b), w.Result().Header
}

func TestStartupRendersRatherThanBlanking(t *testing.T) {
	code, body, _ := get(t, Handler(NewState()), "/")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	if !strings.Contains(body, "Starting up") {
		t.Errorf("a fresh sensor did not render a starting-up state:\n%s", body)
	}
}

func TestClearNetworkSaysAllClear(t *testing.T) {
	s := NewState()
	s.Update(Update{
		Network: "home", Trust: "home", When: time.Now(),
		Areas: []Area{{Key: "router", Name: "Your router", State: "ok", Line: "fine"}},
	})
	code, body, _ := get(t, Handler(s), "/")
	if code != 200 || !strings.Contains(body, "All clear") {
		t.Errorf("clean network did not say all clear:\n%s", body)
	}
}

func TestAlertShowsTitleAndAction(t *testing.T) {
	s := NewState()
	s.Update(Update{
		Network: "home", When: time.Now(),
		Alerts: []verdict.Alert{{
			Target: "10.0.4.1", Band: verdict.High, Score: 60,
			Findings: []probe.Finding{{
				Probe: "arp", Vector: "arp/gateway-mac-changed", Score: 60,
				Title:    "Something else is claiming to be your router",
				Evidence: map[string]string{"what_to_do": "avoid logging in until this clears"},
			}},
		}},
	})
	code, body, _ := get(t, Handler(s), "/")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	for _, want := range []string{"Something needs your attention",
		"claiming to be your router", "avoid logging in"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

// The dashboard renders untrusted input - device names, evidence values a
// hostile host put on the wire. It must escape them, or the status page becomes
// an injection vector on the LAN.
func TestUntrustedContentIsEscaped(t *testing.T) {
	s := NewState()
	s.Update(Update{
		Network: "home", When: time.Now(),
		Alerts: []verdict.Alert{{
			Target: "x", Band: verdict.High, Score: 60,
			Findings: []probe.Finding{{
				Probe: "nameres", Vector: "nameres/answers-everything", Score: 60,
				Title:    "evil",
				Evidence: map[string]string{"names": "<script>alert(1)</script>"},
			}},
		}},
	})
	_, body, _ := get(t, Handler(s), "/")
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("a script tag from the wire was rendered unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("the value was neither escaped nor present; check it is actually rendered")
	}
}

func TestDevicesPageEscapesNames(t *testing.T) {
	s := NewState()
	s.Update(Update{
		Network: "home", When: time.Now(),
		Devices: []Device{{IP: "10.0.4.5", MAC: "aa:bb", Name: "<b>x</b>", FirstSeen: time.Now()}},
	})
	_, body, _ := get(t, Handler(s), "/devices")
	if strings.Contains(body, "<b>x</b>") {
		t.Fatal("a device name was rendered unescaped")
	}
}

// A status page about interception must not itself relax the browser.
func TestSecurityHeaders(t *testing.T) {
	_, _, h := get(t, Handler(NewState()), "/")
	csp := h.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP missing or too loose: %q", csp)
	}
	if strings.Contains(csp, "http://") || strings.Contains(csp, "https://") {
		t.Errorf("CSP names an external origin, which defeats the point: %q", csp)
	}
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}
}

func TestHealthzIsMachineReadable(t *testing.T) {
	s := NewState()
	s.Update(Update{Network: "home", When: time.Now()})
	code, body, _ := get(t, Handler(s), "/healthz")
	if code != 200 || !strings.Contains(body, "state ok") {
		t.Errorf("healthz = %d %q", code, body)
	}
}

func TestUnknownPathIs404(t *testing.T) {
	if code, _, _ := get(t, Handler(NewState()), "/nope"); code != 404 {
		t.Errorf("status %d, want 404", code)
	}
}

// A routine Info-band finding (a certificate rotating) must NOT put the
// dashboard into an "attention" headline or list it under "needs your
// attention". This was a real false alarm: github rotates its leaf constantly
// and the page went amber over it.
func TestInfoBandFindingDoesNotAlarm(t *testing.T) {
	s := NewState()
	s.Update(Update{
		Network: "home", When: time.Now(),
		Alerts: []verdict.Alert{{
			Target: "github.com", Band: verdict.Info, Score: 5,
			Findings: []probe.Finding{{
				Probe: "tls", Vector: "tls/leaf-rotated", Score: 5,
				Title: "The certificate for github.com changed, from the same issuer",
			}},
		}},
	})
	// The activity log renders one entry per event with its kind as a class, and
	// an alert-kind entry is exactly what a page in this state carries: an
	// earlier alert that has since cleared. It must not collide with the
	// assertion below, which guards a real past false alarm - github rotates its
	// leaf constantly and the page went amber over it.
	s.Update(Update{
		Network: "home", When: time.Now(),
		Alerts: []verdict.Alert{{
			Target: "github.com", Band: verdict.Info, Score: 5,
			Findings: []probe.Finding{{
				Probe: "tls", Vector: "tls/leaf-rotated", Score: 5,
				Title: "The certificate for github.com changed, from the same issuer",
			}},
		}},
		Events: []Event{{When: time.Now(), Kind: "alert", Text: "an earlier alert, since cleared"}},
	})

	_, body, _ := get(t, Handler(s), "/")
	if strings.Contains(body, "Something looks unusual") || strings.Contains(body, "Something needs your attention") {
		t.Errorf("an Info-band leaf rotation put the headline into attention:\n%s", head(body, 600))
	}
	if !strings.Contains(body, "All clear") {
		t.Error("headline should be All clear over a routine Info finding")
	}
	if strings.Contains(body, "class=\"alert\"") {
		t.Error("an Info-band finding was listed under needs-your-attention")
	}
	if !strings.Contains(body, "log-alert") {
		t.Error("the activity entry vanished; the log must still record what happened when the headline is calm")
	}
}

func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
