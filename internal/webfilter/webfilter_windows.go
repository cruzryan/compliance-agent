//go:build windows

package webfilter

import (
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unicode/utf16"
)

// The adapters changed: every physical adapter that is up (Wi-Fi and
// Ethernet). Virtual adapters (VPN, Hyper-V, WSL) keep their own DNS.
const adapters = `Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface }`

// The filter's servers and its encrypted (DNS over HTTPS) address, as
// PowerShell. Cloudflare publishes security.cloudflare-dns.com for 1.1.1.2.
const filterVars = `$servers = '1.1.1.2','1.0.0.2','2606:4700:4700::1112','2606:4700:4700::1002'
$template = 'https://security.cloudflare-dns.com/dns-query'`

// Where Windows keeps one adapter's DNS over HTTPS choice for one server: the
// same key Settings > Network > DNS over HTTPS writes. DohFlags 1 is "On
// (automatic template)", with no fallback to plain DNS.
const dohKey = `"HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$guid\DohInterfaceSettings\$(if ($s.Contains(':')) { 'Doh6' } else { 'Doh' })\$s"`

// The exact command shown in the window and run by "Run it for me".
//
// Plain DNS alone is not enough: some routers answer every lookup on port 53
// themselves, whatever server Windows asks (prod, 23 Nov 2026), and then the
// filter never sees a lookup. Encrypted DNS goes to Cloudflare on port 443,
// which a router cannot answer in its place. No fallback to plain DNS: if the
// encrypted lookup fails, Windows does not quietly go around the filter.
var applyCommand = filterVars + `
# Encrypted DNS (DNS over HTTPS) to Cloudflare's malware filter, never plain DNS
foreach ($s in $servers) {
  if (Get-DnsClientDohServerAddress -ServerAddress $s -ErrorAction SilentlyContinue) {
    Set-DnsClientDohServerAddress -ServerAddress $s -DohTemplate $template -AllowFallbackToUdp $false -AutoUpgrade $true | Out-Null
  } else {
    Add-DnsClientDohServerAddress -ServerAddress $s -DohTemplate $template -AllowFallbackToUdp $false -AutoUpgrade $true | Out-Null
  }
}
# The filter as the DNS of each Wi-Fi and Ethernet adapter, encrypted on each
foreach ($a in ` + adapters + `) {
  Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $servers
  $guid = "$($a.InterfaceGuid)"
  foreach ($s in $servers) {
    $key = ` + dohKey + `
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name DohFlags -Value 1 -PropertyType QWord -Force | Out-Null
  }
}
Clear-DnsClientCache`

// Reads, before the change, each adapter's own DNS servers and DNS over HTTPS
// choices, and Windows' encrypted DNS list for the filter's servers. An
// empty server value means "automatic" (from the network), restored as that.
const backupScript = `$ErrorActionPreference = 'Stop'
` + filterVars + `
$rows = @()
foreach ($a in ` + adapters + `) {
  $guid = "$($a.InterfaceGuid)"
  $v4 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" -Name NameServer -ErrorAction SilentlyContinue).NameServer
  $v6 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$guid" -Name NameServer -ErrorAction SilentlyContinue).NameServer
  $flags = @()
  foreach ($s in $servers) {
    $key = ` + dohKey + `
    $f = (Get-ItemProperty -Path $key -Name DohFlags -ErrorAction SilentlyContinue).DohFlags
    if ($null -ne $f) { $flags += [pscustomobject]@{ server = $s; flags = [int64]$f } }
  }
  $rows += [pscustomobject]@{ guid = $guid; name = "$($a.Name)"; v4 = "$v4"; v6 = "$v6"; doh = @($flags) }
}
$known = @()
foreach ($s in $servers) {
  $e = Get-DnsClientDohServerAddress -ServerAddress $s -ErrorAction SilentlyContinue
  if ($e) { $known += [pscustomobject]@{ server = $s; template = "$($e.DohTemplate)"; fallback = [bool]$e.AllowFallbackToUdp; auto = [bool]$e.AutoUpgrade } }
}
ConvertTo-Json -Depth 5 -Compress -InputObject ([pscustomobject]@{ adapters = @($rows); doh = @($known) })`

// Puts back what was saved: each adapter's servers (found by GUID, indexes
// change) and DNS over HTTPS choices, and Windows' encrypted DNS list. A
// backup from 0.2.0 holds only the adapters' servers; 0.2.0 added no
// encrypted DNS, so anything for the filter's servers is the agent's own.
const restoreScript = `$ErrorActionPreference = 'Stop'
` + filterVars + `
$saved = $env:CA_BACKUP | ConvertFrom-Json
if ($saved -is [array] -or $null -eq $saved.adapters) { $rows = @($saved); $known = @() } else { $rows = @($saved.adapters); $known = @($saved.doh) }
foreach ($row in $rows) {
  $a = Get-NetAdapter | Where-Object { "$($_.InterfaceGuid)" -eq $row.guid }
  if (-not $a) { continue }
  $names = @(("$($row.v4) $($row.v6)" -split '[,\s]+') | Where-Object { $_ })
  if ($names.Count -gt 0) {
    Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $names
  } else {
    Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses
  }
  $guid = "$($a.InterfaceGuid)"
  foreach ($s in $servers) {
    $key = ` + dohKey + `
    $before = @($row.doh) | Where-Object { $_ -and $_.server -eq $s } | Select-Object -First 1
    if ($before) {
      New-Item -Path $key -Force | Out-Null
      New-ItemProperty -Path $key -Name DohFlags -Value ([int64]$before.flags) -PropertyType QWord -Force | Out-Null
    } elseif (Test-Path $key) {
      Remove-Item -Path $key -Recurse -Force
    }
  }
}
foreach ($s in $servers) {
  $before = @($known) | Where-Object { $_ -and $_.server -eq $s } | Select-Object -First 1
  if ($before) {
    Set-DnsClientDohServerAddress -ServerAddress $s -DohTemplate $before.template -AllowFallbackToUdp ([bool]$before.fallback) -AutoUpgrade ([bool]$before.auto) | Out-Null
  } elseif (Get-DnsClientDohServerAddress -ServerAddress $s -ErrorAction SilentlyContinue) {
    Remove-DnsClientDohServerAddress -ServerAddress $s -Confirm:$false
  }
}
Clear-DnsClientCache`

const undoCommand = `# For each adapter changed: the DNS servers it had before, or automatic
Set-DnsClientServerAddress -InterfaceIndex <adapter> -ServerAddresses <saved servers>
Set-DnsClientServerAddress -InterfaceIndex <adapter> -ResetServerAddresses
# Encrypted DNS: the choices saved before, or removed if there were none
Remove-DnsClientDohServerAddress -ServerAddress <filter server>
Clear-DnsClientCache`

func planOS() Plan {
	return Plan{
		Supported: true,
		Method:    "windows-dns",
		Commands:  []string{applyCommand},
		Undo:      []string{undoCommand},
		Prompt:    "none",
		Applies:   "Wi-Fi and Ethernet",
	}
}

func powershell(script string, env ...string) (string, error) {
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 0, len(units)*2)
	for _, u := range units {
		raw = append(raw, byte(u), byte(u>>8))
	}
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw))
	command.Env = append(os.Environ(), env...)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := command.CombinedOutput()
	text := strings.TrimSpace(string(output))
	if err != nil {
		if text == "" {
			text = err.Error()
		}
		return "", errors.New("Windows could not change the DNS: " + firstLine(text))
	}
	return text, nil
}

func currentServers() ([]byte, error) {
	out, err := powershell(backupScript)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(out, "{") {
		return nil, errors.New("Windows returned an unreadable list of network adapters")
	}
	return []byte(out), nil
}

func applyFilter() error {
	_, err := powershell("$ErrorActionPreference = 'Stop'\n" + applyCommand)
	return err
}

func restoreServers(backup []byte) error {
	_, err := powershell(restoreScript, "CA_BACKUP="+string(backup))
	return err
}

func firstLine(text string) string {
	line, _, _ := strings.Cut(text, "\n")
	if len(line) > 200 {
		line = line[:200]
	}
	return strings.TrimSpace(line)
}
