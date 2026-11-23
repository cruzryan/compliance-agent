//go:build linux

package webfilter

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
)

// Linux has no single DNS setting. The agent changes it where the desktop
// keeps it: NetworkManager (Ubuntu, Fedora, most desktops) per connection, or
// systemd-resolved globally. Anything else gets the steps to do it by hand.

const resolvedDropIn = "/etc/systemd/resolved.conf.d/compliance-agent-web-filtering.conf"

type savedConnection struct {
	UUID      string `json:"uuid"`
	Name      string `json:"name"`
	DNS4      string `json:"dns4"`
	Ignore4   string `json:"ignore4"`
	DNS6      string `json:"dns6"`
	Ignore6   string `json:"ignore6"`
	Resolved  bool   `json:"resolved,omitempty"`
	HadDropIn bool   `json:"had_drop_in,omitempty"`
}

type connection struct{ uuid, name string }

func networkManagerRunning() bool {
	if _, err := exec.LookPath("nmcli"); err != nil {
		return false
	}
	out, err := exec.Command("nmcli", "-t", "-f", "RUNNING", "general").Output()
	return err == nil && strings.TrimSpace(string(out)) == "running"
}

func resolvedRunning() bool {
	if _, err := os.Stat("/run/systemd/resolve"); err != nil {
		return false
	}
	return exec.Command("systemctl", "is-active", "--quiet", "systemd-resolved").Run() == nil
}

// activeConnections are the active Wi-Fi and Ethernet connections.
func activeConnections() ([]connection, error) {
	out, err := exec.Command("nmcli", "-t", "-f", "UUID,TYPE,NAME", "connection", "show", "--active").Output()
	if err != nil {
		return nil, errors.New("NetworkManager could not list the active connections")
	}
	var list []connection
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[1] == "802-11-wireless" || parts[1] == "802-3-ethernet" {
			list = append(list, connection{uuid: parts[0], name: parts[2]})
		}
	}
	return list, nil
}

func nmApplyScript(list []connection) string {
	var b strings.Builder
	for _, c := range list {
		b.WriteString("nmcli connection modify " + shellQuote(c.uuid) +
			" ipv4.dns " + shellQuote(strings.Join(Servers4, " ")) + " ipv4.ignore-auto-dns yes" +
			" ipv6.dns " + shellQuote(strings.Join(Servers6, " ")) + " ipv6.ignore-auto-dns yes\n")
		b.WriteString("nmcli connection up " + shellQuote(c.uuid) + "\n")
	}
	return strings.TrimSpace(b.String())
}

func resolvedApplyScript() string {
	servers := strings.Join(append(append([]string(nil), Servers4...), Servers6...), " ")
	return "mkdir -p /etc/systemd/resolved.conf.d\n" +
		"printf '%s\\n' '[Resolve]' 'DNS=" + servers + "' 'Domains=~.' > " + resolvedDropIn + "\n" +
		"systemctl restart systemd-resolved"
}

var manualSteps = []string{
	"Open your network settings and choose your Wi-Fi or Ethernet connection.",
	"In its IPv4 settings, turn off automatic DNS and enter 1.1.1.2, 1.0.0.2.",
	"In its IPv6 settings, turn off automatic DNS and enter 2606:4700:4700::1112, 2606:4700:4700::1002.",
	"Save and reconnect. Compliance Agent sees the change on its next check.",
}

func planOS() Plan {
	if _, err := exec.LookPath("pkexec"); err != nil {
		return Plan{Supported: false, Method: "manual", Prompt: "password", Steps: manualSteps}
	}
	if networkManagerRunning() {
		list, err := activeConnections()
		if err == nil && len(list) > 0 {
			names := make([]string, len(list))
			for i, c := range list {
				names[i] = c.name
			}
			return Plan{
				Supported: true,
				Method:    "linux-networkmanager",
				Commands:  strings.Split(nmApplyScript(list), "\n"),
				Undo:      []string{"nmcli connection modify <connection> ipv4.dns <saved> ipv4.ignore-auto-dns <saved> ipv6.dns <saved> ipv6.ignore-auto-dns <saved>"},
				Prompt:    "password",
				Applies:   strings.Join(names, ", "),
			}
		}
	}
	if resolvedRunning() {
		return Plan{
			Supported: true,
			Method:    "linux-resolved",
			Commands:  strings.Split(resolvedApplyScript(), "\n"),
			Undo:      []string{"rm " + resolvedDropIn, "systemctl restart systemd-resolved"},
			Prompt:    "password",
			Applies:   "every connection",
		}
	}
	return Plan{Supported: false, Method: "manual", Prompt: "password", Steps: manualSteps}
}

func nmValue(uuid, field string) string {
	out, err := exec.Command("nmcli", "-g", field, "connection", "show", uuid).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func currentServers() ([]byte, error) {
	plan := planOS()
	switch plan.Method {
	case "linux-networkmanager":
		list, err := activeConnections()
		if err != nil {
			return nil, err
		}
		saved := make([]savedConnection, 0, len(list))
		for _, c := range list {
			saved = append(saved, savedConnection{
				UUID: c.uuid, Name: c.name,
				DNS4: nmValue(c.uuid, "ipv4.dns"), Ignore4: nmValue(c.uuid, "ipv4.ignore-auto-dns"),
				DNS6: nmValue(c.uuid, "ipv6.dns"), Ignore6: nmValue(c.uuid, "ipv6.ignore-auto-dns"),
			})
		}
		return json.Marshal(saved)
	case "linux-resolved":
		_, err := os.Stat(resolvedDropIn)
		return json.Marshal([]savedConnection{{Resolved: true, HadDropIn: err == nil}})
	}
	return nil, errors.New("Compliance Agent can't change the DNS on this computer")
}

// runAsAdmin runs a shell script after the system asks for the person's
// password (polkit). The script is one argument, never spliced into a shell.
func runAsAdmin(script string) error {
	if err := exec.Command("pkexec", "/bin/sh", "-c", script).Run(); err != nil {
		return errors.New("The DNS was not changed. Linux did not get permission, or the change failed.")
	}
	return nil
}

func applyFilter() error {
	plan := planOS()
	switch plan.Method {
	case "linux-networkmanager":
		list, err := activeConnections()
		if err != nil {
			return err
		}
		return runAsAdmin(nmApplyScript(list))
	case "linux-resolved":
		return runAsAdmin(resolvedApplyScript())
	}
	return errors.New("Compliance Agent can't change the DNS on this computer")
}

func yesNo(value string) string {
	if value == "yes" {
		return "yes"
	}
	return "no"
}

func restoreServers(backup []byte) error {
	var saved []savedConnection
	if err := json.Unmarshal(backup, &saved); err != nil {
		return errors.New("the saved DNS servers are unreadable")
	}
	var b strings.Builder
	for _, c := range saved {
		if c.Resolved {
			if !c.HadDropIn {
				b.WriteString("rm -f " + resolvedDropIn + "\n")
			}
			b.WriteString("systemctl restart systemd-resolved\n")
			continue
		}
		b.WriteString("nmcli connection modify " + shellQuote(c.UUID) +
			" ipv4.dns " + shellQuote(strings.ReplaceAll(c.DNS4, ",", " ")) + " ipv4.ignore-auto-dns " + yesNo(c.Ignore4) +
			" ipv6.dns " + shellQuote(strings.ReplaceAll(c.DNS6, ",", " ")) + " ipv6.ignore-auto-dns " + yesNo(c.Ignore6) + "\n")
		b.WriteString("nmcli connection up " + shellQuote(c.UUID) + "\n")
	}
	return runAsAdmin(strings.TrimSpace(b.String()))
}
