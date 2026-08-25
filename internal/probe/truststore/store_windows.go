//go:build windows

package truststore

import (
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Both stores matter. Windows resolves trust from the machine store and the
// per-user store, and the per-user one is the more interesting of the two: a
// root can be planted there without administrator rights.
//
// ponytail: PowerShell rather than wincrypt via x/sys/windows. One process per
// two-minute interval is cheap, and CertEnumCertificatesInStore would be ~80
// lines of syscall wrapping for the same bytes.
const psRoots = `
$ErrorActionPreference = 'SilentlyContinue'
foreach ($s in @('LocalMachine','CurrentUser')) {
  Get-ChildItem "Cert:\$s\Root" | ForEach-Object {
    "$s\Root " + [Convert]::ToBase64String($_.RawData)
  }
}
`

func systemRoots(ctx context.Context) ([]rawRoot, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-Command", psRoots).Output()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("reading the Windows certificate stores: %w", err)
	}

	var roots []rawRoot
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		store, b64, ok := strings.Cut(line, " ")
		if !ok || b64 == "" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		roots = append(roots, rawRoot{DER: der, Store: store})
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("no certificates returned from the Windows root stores")
	}
	return roots, nil
}
