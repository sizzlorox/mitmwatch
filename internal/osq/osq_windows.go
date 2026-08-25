//go:build windows

package osq

import (
	"context"
	"encoding/json"
)

// One PowerShell invocation gathers everything: spawning powershell.exe costs
// far more than the queries themselves.
//
// ponytail: shelling out to PowerShell instead of the IP Helper API. The API
// is the right answer if this ever runs per-second; for a 5-minute canary it
// is not worth the syscall wrappers.
const psQuery = `
$ErrorActionPreference = 'SilentlyContinue'
$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1
$out = [ordered]@{ iface=''; ssid=''; gateway_ip=''; gateway_mac=''; dhcp_server=''; resolvers=@() }
if ($r) {
  $out.gateway_ip = [string]$r.NextHop
  $ad = Get-NetAdapter -InterfaceIndex $r.ifIndex
  if ($ad) { $out.iface = [string]$ad.Name }
  $nb = Get-NetNeighbor -IPAddress $r.NextHop -InterfaceIndex $r.ifIndex | Where-Object { $_.LinkLayerAddress } | Select-Object -First 1
  if ($nb) { $out.gateway_mac = [string]$nb.LinkLayerAddress }
  $dns = Get-DnsClientServerAddress -InterfaceIndex $r.ifIndex | Select-Object -ExpandProperty ServerAddresses
  if ($dns) { $out.resolvers = @($dns) }
  $cfg = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.InterfaceIndex -eq $r.ifIndex }
  if ($cfg -and $cfg.DHCPServer) { $out.dhcp_server = [string]$cfg.DHCPServer }
}
$w = netsh wlan show interfaces 2>$null
if ($w) {
  $m = [regex]::Match(($w -join "` + "`n" + `"), '(?m)^\s*SSID\s*:\s*(.+)$')
  if ($m.Success) { $out.ssid = $m.Groups[1].Value.Trim() }
}
$out | ConvertTo-Json -Compress
`

func identify(ctx context.Context) (NetworkIdentity, error) {
	var n NetworkIdentity
	out, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psQuery)
	if err != nil && out == "" {
		n.Missing = []string{"iface", "ssid", "gateway_ip", "gateway_mac", "dhcp_server", "resolvers"}
		return n, err
	}
	var raw struct {
		Iface      string   `json:"iface"`
		SSID       string   `json:"ssid"`
		GatewayIP  string   `json:"gateway_ip"`
		GatewayMAC string   `json:"gateway_mac"`
		DHCPServer string   `json:"dhcp_server"`
		Resolvers  []string `json:"resolvers"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		n.Missing = []string{"all (powershell output unparseable)"}
		return n, err
	}
	n = NetworkIdentity{
		Iface:      raw.Iface,
		SSID:       raw.SSID,
		GatewayIP:  raw.GatewayIP,
		GatewayMAC: normMAC(raw.GatewayMAC),
		DHCPServer: raw.DHCPServer,
		Resolvers:  raw.Resolvers,
	}
	n.Missing = missingOf(n)
	return n, nil
}
