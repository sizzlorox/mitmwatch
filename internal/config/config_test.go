package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWeightsFallBackToDefaults(t *testing.T) {
	c := Defaults()
	if got := c.Weight("tls/private-root"); got != 70 {
		t.Errorf("tls/private-root = %d, want 70", got)
	}
	// An unknown vector must score zero rather than guess, so a typo in a
	// probe can never manufacture an alert.
	if got := c.Weight("nonexistent/vector"); got != 0 {
		t.Errorf("unknown vector scored %d, want 0", got)
	}
}

// Overriding one weight must not drop the rest of the table: recalibrating a
// single number should not silently disable every other detector.
func TestOverridingOneWeightKeepsTheRest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mitmwatch.toml")
	if err := os.WriteFile(path, []byte("[weights]\n\"tls/no-sct\" = 99\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Weight("tls/no-sct"); got != 99 {
		t.Errorf("override not applied: got %d, want 99", got)
	}
	if got := c.Weight("tls/private-root"); got != 70 {
		t.Errorf("unrelated weight was dropped: got %d, want 70", got)
	}
}

func TestMissingFileIsNotAnError(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatalf("a missing config must fall back to defaults, got %v", err)
	}
	if c.Loaded() {
		t.Error("Loaded() reports true for a file that does not exist")
	}
	if len(c.TLS.Pin) == 0 {
		t.Error("defaults did not populate the pin list")
	}
	if !c.Sensor.Audit {
		t.Error("audit should be enabled by default")
	}
}

func TestPartialFileKeepsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mitmwatch.toml")
	if err := os.WriteFile(path, []byte("[sensor]\nrole = \"always-on\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sensor.Role != "always-on" {
		t.Errorf("role = %q, want always-on", c.Sensor.Role)
	}
	if len(c.DNS.DoH) == 0 {
		t.Error("setting one key wiped the defaults for another section")
	}
	if !c.Sensor.Audit {
		t.Error("omitting sensor.audit should preserve its enabled default")
	}
}

func TestAuditCanBeDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mitmwatch.toml")
	if err := os.WriteFile(path, []byte("[sensor]\naudit = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sensor.Audit {
		t.Error("sensor.audit=false did not disable the audit feature")
	}
}
