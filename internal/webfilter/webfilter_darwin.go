//go:build darwin

package webfilter

import (
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
)

type savedService struct {
	Service string   `json:"service"`
	Servers []string `json:"servers"`
}

// services lists the enabled network services (Wi-Fi, Ethernet, ...). The
// first line of the output is a note; a leading * marks a disabled service.
func services() ([]string, error) {
	out, err := exec.Command("/usr/sbin/networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, errors.New("macOS could not list the network services")
	}
	var names []string
	for i, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if i == 0 || line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		names = append(names, line)
	}
	return names, nil
}

func applyScript(names []string) string {
	var b strings.Builder
	servers := strings.Join(append(append([]string(nil), Servers4...), Servers6...), " ")
	for _, name := range names {
		b.WriteString("/usr/sbin/networksetup -setdnsservers " + shellQuote(name) + " " + servers + "\n")
	}
	b.WriteString("/usr/bin/dscacheutil -flushcache; /usr/bin/killall -HUP mDNSResponder")
	return b.String()
}

func planOS() Plan {
	names, err := services()
	if err != nil || len(names) == 0 {
		return Plan{Supported: false, Method: "manual", Prompt: "password", Steps: manualSteps}
	}
	return Plan{
		Supported: true,
		Method:    "macos-networksetup",
		Commands:  strings.Split(applyScript(names), "\n"),
		Undo:      []string{"/usr/sbin/networksetup -setdnsservers <service> <saved servers, or empty for automatic>"},
		Prompt:    "password",
		Applies:   strings.Join(names, ", "),
	}
}

var manualSteps = []string{
	"Open System Settings, then Network.",
	"Choose your network (Wi-Fi or Ethernet), then Details, then DNS.",
	"Remove the servers listed, then add 1.1.1.2 and 1.0.0.2.",
	"Choose OK. Compliance Agent sees the change on its next check.",
}

func currentServers() ([]byte, error) {
	names, err := services()
	if err != nil {
		return nil, err
	}
	saved := make([]savedService, 0, len(names))
	for _, name := range names {
		out, err := exec.Command("/usr/sbin/networksetup", "-getdnsservers", name).Output()
		if err != nil {
			return nil, errors.New("macOS could not read the DNS servers of " + name)
		}
		row := savedService{Service: name, Servers: []string{}}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			// "There aren't any DNS Servers set on Wi-Fi." means automatic.
			if line == "" || strings.Contains(line, " ") {
				continue
			}
			row.Servers = append(row.Servers, line)
		}
		saved = append(saved, row)
	}
	return json.Marshal(saved)
}

// runAsAdmin runs a shell script after macOS asks for the person's password.
// The script is passed as an argument, never spliced into the AppleScript.
func runAsAdmin(script string) error {
	err := exec.Command("/usr/bin/osascript",
		"-e", "on run argv",
		"-e", `do shell script (item 1 of argv) with prompt "Compliance Agent wants to change the DNS to turn web filtering on or off." with administrator privileges`,
		"-e", "end run",
		script).Run()
	if err != nil {
		return errors.New("The DNS was not changed. macOS did not get permission, or the change failed.")
	}
	return nil
}

func applyFilter() error {
	names, err := services()
	if err != nil {
		return err
	}
	return runAsAdmin(applyScript(names))
}

func restoreServers(backup []byte) error {
	var saved []savedService
	if err := json.Unmarshal(backup, &saved); err != nil {
		return errors.New("the saved DNS servers are unreadable")
	}
	var b strings.Builder
	for _, row := range saved {
		servers := "empty"
		if len(row.Servers) > 0 {
			quoted := make([]string, len(row.Servers))
			for i, s := range row.Servers {
				quoted[i] = shellQuote(s)
			}
			servers = strings.Join(quoted, " ")
		}
		b.WriteString("/usr/sbin/networksetup -setdnsservers " + shellQuote(row.Service) + " " + servers + "\n")
	}
	b.WriteString("/usr/bin/dscacheutil -flushcache; /usr/bin/killall -HUP mDNSResponder")
	return runAsAdmin(b.String())
}
