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

// The exact command shown in the window and run by "Run it for me".
var applyCommand = adapters + ` | ForEach-Object {
  Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex ` + "`" + `
    -ServerAddresses 1.1.1.2,1.0.0.2,2606:4700:4700::1112,2606:4700:4700::1002 }
Clear-DnsClientCache`

// Reads each adapter's own DNS servers from the registry. An empty value
// means "automatic" (from the network), which Undo restores as automatic.
const backupScript = `$ErrorActionPreference = 'Stop'
$rows = @()
foreach ($a in ` + adapters + `) {
  $guid = "$($a.InterfaceGuid)"
  $v4 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" -Name NameServer -ErrorAction SilentlyContinue).NameServer
  $v6 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$guid" -Name NameServer -ErrorAction SilentlyContinue).NameServer
  $rows += [pscustomobject]@{ guid = $guid; name = "$($a.Name)"; v4 = "$v4"; v6 = "$v6" }
}
ConvertTo-Json -InputObject @($rows) -Compress`

// Puts back the saved servers, found by adapter GUID (indexes change).
const restoreScript = `$ErrorActionPreference = 'Stop'
$saved = $env:CA_BACKUP | ConvertFrom-Json
foreach ($row in @($saved)) {
  $a = Get-NetAdapter | Where-Object { "$($_.InterfaceGuid)" -eq $row.guid }
  if (-not $a) { continue }
  $servers = @(("$($row.v4) $($row.v6)" -split '[,\s]+') | Where-Object { $_ })
  if ($servers.Count -gt 0) {
    Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $servers
  } else {
    Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses
  }
}
Clear-DnsClientCache`

const undoCommand = `# For each adapter changed: the DNS servers it had before, or automatic
Set-DnsClientServerAddress -InterfaceIndex <adapter> -ServerAddresses <saved servers>
Set-DnsClientServerAddress -InterfaceIndex <adapter> -ResetServerAddresses
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
	if !strings.HasPrefix(out, "[") {
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
