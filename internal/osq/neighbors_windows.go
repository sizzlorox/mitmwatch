//go:build windows

package osq

import (
	"context"
	"strings"
)

// One record per line rather than ConvertTo-Json.
//
// Windows PowerShell 5.1 has no -AsArray, and ConvertTo-Json emits a bare
// object rather than a one-element array when exactly one neighbour matches -
// so a parse that works on a busy LAN fails on a quiet one. Lines have neither
// failure mode.
//
// The separator is "|" and not a tab because PowerShell spells a tab with a
// backtick, and a backtick cannot appear inside a Go raw string literal.
// Neither an address, a MAC, nor a Windows adapter name contains "|".
const psNeighbors = `
$ErrorActionPreference = 'SilentlyContinue'
Get-NetNeighbor -AddressFamily IPv4 |
  Where-Object { $_.LinkLayerAddress -and $_.State -in 'Reachable','Stale','Permanent' } |
  ForEach-Object {
    $if = (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex).Name
    "$($_.IPAddress)|$($_.LinkLayerAddress)|$if"
  }
`

func neighbors(ctx context.Context) ([]Neighbor, error) {
	out, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psNeighbors)
	if err != nil && out == "" {
		return nil, err
	}
	var ns []Neighbor
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), "|")
		if len(f) < 2 {
			continue
		}
		mac := normMAC(f[1])
		if mac == "" {
			continue
		}
		n := Neighbor{IP: strings.TrimSpace(f[0]), MAC: mac}
		if len(f) > 2 {
			n.Iface = strings.TrimSpace(f[2])
		}
		ns = append(ns, n)
	}
	return ns, nil
}
