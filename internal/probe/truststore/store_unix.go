//go:build linux || darwin

package truststore

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// bundlePaths are the concatenated-PEM trust stores the common distributions
// use, plus the directories a local administrator adds roots to. The last two
// entries are the ones an injected root actually lands in, so they are read
// even when a distribution bundle was already found.
var bundlePaths = []string{
	"/etc/ssl/certs/ca-certificates.crt", // debian, ubuntu
	"/etc/pki/tls/certs/ca-bundle.crt",   // rhel, fedora
	"/etc/ssl/cert.pem",                  // alpine, some bsd layouts
	"/etc/ssl/ca-bundle.pem",             // suse
}

var localDirs = []string{
	"/usr/local/share/ca-certificates", // debian, ubuntu: where `update-ca-certificates` picks up additions
	"/etc/pki/ca-trust/source/anchors", // rhel, fedora: same role
}

// macKeychains are read with the `security` tool; there is no file to parse.
var macKeychains = []string{
	"/System/Library/Keychains/SystemRootCertificates.keychain",
	"/Library/Keychains/System.keychain",
}

func systemRoots(ctx context.Context) ([]rawRoot, error) {
	if runtime.GOOS == "darwin" {
		return darwinRoots(ctx)
	}
	return linuxRoots()
}

// linuxRoots reads every trust store that exists on this distribution.
//
// A path that is simply absent is not a failure - no distribution has all of
// them. A path that exists and cannot be read IS a failure, and is reported
// alongside whatever was read, because a silently short root set becomes a
// baseline that says the missing roots were never there.
func linuxRoots() ([]rawRoot, error) {
	var (
		out    []rawRoot
		failed []string
	)

	for _, p := range bundlePaths {
		b, err := os.ReadFile(p)
		if err != nil {
			if !os.IsNotExist(err) {
				failed = append(failed, fmt.Sprintf("%s: %v", p, err))
			}
			continue
		}
		out = append(out, decodePEM(b, p)...)
	}
	for _, dir := range localDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if !os.IsNotExist(err) {
				failed = append(failed, fmt.Sprintf("%s: %v", dir, err))
			}
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s/%s: %v", dir, e.Name(), err))
				continue
			}
			out = append(out, decodePEM(b, dir)...)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no trust store found in any of %v", bundlePaths)
	}
	if len(failed) > 0 {
		return out, fmt.Errorf("read %d root(s) but %d source(s) failed: %s",
			len(out), len(failed), strings.Join(failed, "; "))
	}
	return out, nil
}

func darwinRoots(ctx context.Context) ([]rawRoot, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var (
		out    []rawRoot
		failed []string
	)
	for _, kc := range macKeychains {
		b, err := exec.CommandContext(ctx, "security", "find-certificate", "-a", "-p", kc).Output()
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", kc, err))
			continue
		}
		out = append(out, decodePEM(b, kc)...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificates returned from %v", macKeychains)
	}
	if len(failed) > 0 {
		return out, fmt.Errorf("read %d certificate(s) but %d keychain(s) failed: %s",
			len(out), len(failed), strings.Join(failed, "; "))
	}
	return out, nil
}

func decodePEM(b []byte, store string) []rawRoot {
	var out []rawRoot
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return out
		}
		if blk.Type == "CERTIFICATE" {
			out = append(out, rawRoot{DER: blk.Bytes, Store: store})
		}
	}
}
