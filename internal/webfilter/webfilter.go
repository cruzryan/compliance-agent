// Package webfilter checks whether this computer filters malware and phishing
// sites at DNS (ISO 27001 A.8.23, web filtering), and turns Cloudflare's
// malware filter on or off when the person presses the button for it. On
// Windows it is turned on as encrypted DNS (DNS over HTTPS, no fallback to
// plain DNS), so a router that redirects plain DNS cannot bypass it.
//
// The check is read-only: it asks the computer's own DNS for a test domain
// that every filtering service blocks. A filtering DNS answers 0.0.0.0 (or
// refuses to answer); an unfiltered one gives the domain's real address.
//
// Turning it on changes one setting, the DNS servers, and nothing else. The
// previous servers are saved first, so Undo puts them back exactly. It only
// ever runs because the person pressed the button and, on macOS and Linux,
// typed their password in the system's own prompt. It is never reapplied on
// its own: if someone turns it off later, the agent tells them once.
package webfilter

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TestDomain is Cloudflare's published test domain for its malware filter.
const TestDomain = "malware.testcategory.com"

// Cloudflare's malware-blocking resolvers (1.1.1.2 "for Families", malware only).
var (
	Servers4 = []string{"1.1.1.2", "1.0.0.2"}
	Servers6 = []string{"2606:4700:4700::1112", "2606:4700:4700::1002"}
)

// Check results.
const (
	StateOn      = "on"
	StateOff     = "off"
	StateUnknown = "unknown"
)

// Status is the result of one check.
type Status struct {
	State  string `json:"state"`
	Detail string `json:"detail"`
	// Redirected is true when the network answers DNS questions meant for
	// Cloudflare's filter itself, so setting the filter's servers alone
	// changes nothing on this network (prod, 23 Nov 2026: a Totalplay router
	// answered every lookup on port 53, whatever server Windows asked).
	Redirected bool      `json:"redirected,omitempty"`
	CheckedAt  time.Time `json:"checked_at"`
}

// lookupFn is swapped out by tests.
var lookupFn = func(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// filterLookupFn asks Cloudflare's filter directly over plain DNS (port 53),
// bypassing this computer's settings. The real filter answers 0.0.0.0 for the
// test domain; a real address means something on the network answered in its
// place. Swapped out by tests.
var filterLookupFn = func(ctx context.Context, host string) ([]net.IPAddr, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", net.JoinHostPort(Servers4[0], "53"))
		},
	}
	return resolver.LookupIPAddr(ctx, host)
}

// RedirectedDetail is what the window says when the network redirects DNS.
const RedirectedDetail = "A known malware test site still opens: your network answers DNS lookups itself, so the filter never sees them."

// Check asks this computer's DNS for the test domain. When it is not
// filtered, it also asks the filter directly, to tell "no filter set" from
// "the network redirects DNS".
func Check(ctx context.Context) Status {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	addrs, err := lookupFn(ctx, TestDomain)
	status := classify(addrs, err)
	if status.State == StateOff && networkRedirects(ctx) {
		status.Redirected = true
		status.Detail = RedirectedDetail
	}
	status.CheckedAt = time.Now().UTC()
	return status
}

// networkRedirects is true only when the filter's own address gave a real
// address for the test domain. No answer, or a blocked one, is not proof.
func networkRedirects(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := filterLookupFn(ctx, TestDomain)
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if !addr.IP.IsUnspecified() {
			return true
		}
	}
	return false
}

// classify turns a DNS answer into on, off or unknown. A timeout or a broken
// network is unknown, never off: an outage is not a missing setting.
func classify(addrs []net.IPAddr, err error) Status {
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return Status{State: StateOn, Detail: "A known malware test site is blocked: this computer's DNS refuses to answer for it."}
		}
		return Status{State: StateUnknown, Detail: "We couldn't reach this computer's DNS to check. We'll check again later."}
	}
	if len(addrs) == 0 {
		return Status{State: StateOn, Detail: "A known malware test site is blocked: this computer's DNS gives no address for it."}
	}
	for _, addr := range addrs {
		if !addr.IP.IsUnspecified() {
			return Status{State: StateOff, Detail: "A known malware test site still opens: this computer's DNS does not filter malware sites."}
		}
	}
	return Status{State: StateOn, Detail: "A known malware test site is blocked by this computer's DNS."}
}

// Plan says how this computer would be changed, in the exact commands the
// window shows before the person agrees.
type Plan struct {
	// Supported is false when the agent cannot make the change itself; Steps
	// then say how to do it by hand.
	Supported bool     `json:"supported"`
	Method    string   `json:"method"`
	Commands  []string `json:"commands"`
	Undo      []string `json:"undo"`
	// Prompt is what the system asks before the change: "none" when the agent
	// already runs with administrator rights (Windows), "password" otherwise.
	Prompt string   `json:"prompt"`
	Steps  []string `json:"steps,omitempty"`
	// Where the change applies, in words ("Wi-Fi and Ethernet").
	Applies string `json:"applies,omitempty"`
	// TurnedOnByAgent is true when this agent made the change, so Undo can put
	// back what was there before.
	TurnedOnByAgent bool       `json:"turned_on_by_agent"`
	TurnedOnAt      *time.Time `json:"turned_on_at,omitempty"`
}

// watchState is remembered between checks.
type watchState struct {
	SeenOn          bool       `json:"seen_on"`
	OffTold         bool       `json:"off_told"`
	TurnedOnByAgent bool       `json:"turned_on_by_agent"`
	TurnedOnAt      *time.Time `json:"turned_on_at,omitempty"`
}

func statePath(dir string) string  { return filepath.Join(dir, "webfilter.json") }
func backupPath(dir string) string { return filepath.Join(dir, "webfilter-backup.json") }

func loadWatch(dir string) watchState {
	var w watchState
	data, err := os.ReadFile(statePath(dir))
	if err != nil || json.Unmarshal(data, &w) != nil {
		return watchState{}
	}
	return w
}

func saveWatch(dir string, w watchState) error {
	data, err := json.Marshal(w)
	if err != nil {
		return err
	}
	return writeFileAtomic(statePath(dir), data)
}

// Watch records one check and says whether to tell the person that web
// filtering was turned off. That happens once each time it goes from on to
// off; it is never told twice in a row, and never on a computer where it was
// never on (the window already shows that).
func Watch(dir string, status Status) (tellOff bool, err error) {
	w := loadWatch(dir)
	switch status.State {
	case StateOn:
		if w.SeenOn && !w.OffTold {
			return false, nil
		}
		w.SeenOn, w.OffTold = true, false
	case StateOff:
		if !w.SeenOn || w.OffTold {
			return false, nil
		}
		w.OffTold = true
		tellOff = true
	default:
		return false, nil
	}
	// Remember first, then tell: a crash can lose the message, never repeat it.
	return tellOff, saveWatch(dir, w)
}

// PlanFor is this computer's plan, with whether the agent turned it on.
func PlanFor(dir string) Plan {
	p := planOS()
	w := loadWatch(dir)
	p.TurnedOnByAgent = w.TurnedOnByAgent
	p.TurnedOnAt = w.TurnedOnAt
	return p
}

// TurnOn saves the current DNS servers and switches to Cloudflare's filter.
func TurnOn(dir string) error {
	plan := planOS()
	if !plan.Supported {
		return errors.New("Compliance Agent can't change the DNS on this computer. Follow the steps shown to turn on web filtering yourself.")
	}
	backup, err := currentServers()
	if err != nil {
		return err
	}
	// Keep the oldest backup: pressing the button twice must not save the
	// filter's own servers as "what was there before".
	if _, statErr := os.Stat(backupPath(dir)); statErr != nil {
		if err := writeFileAtomic(backupPath(dir), backup); err != nil {
			return err
		}
	}
	if err := applyFilter(); err != nil {
		return err
	}
	now := time.Now().UTC()
	w := loadWatch(dir)
	w.TurnedOnByAgent, w.TurnedOnAt = true, &now
	w.SeenOn, w.OffTold = true, false
	return saveWatch(dir, w)
}

// TurnOff puts back the DNS servers saved when the agent turned it on.
func TurnOff(dir string) error {
	backup, err := os.ReadFile(backupPath(dir))
	if err != nil {
		return errors.New("Compliance Agent didn't turn on web filtering on this computer, so there is nothing to undo here.")
	}
	if err := restoreServers(backup); err != nil {
		return err
	}
	_ = os.Remove(backupPath(dir))
	// Undo is the person's choice: forget that it was on, so it is not
	// reported as "turned off" afterwards.
	return saveWatch(dir, watchState{})
}

// shellQuote quotes one argument for /bin/sh.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
