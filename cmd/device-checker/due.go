package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hackzero/device-checker/internal/notify"
	"github.com/hackzero/device-checker/internal/webfilter"
)

// ---------------------------------------------------------------- what is due
//
// `due` asks the service what the company has due (signed with this device's
// key, read-only on the service), tells the person once about a new task or a
// task that just became late, checks web filtering when the workspace needs
// it, and saves the answer for the window. `due --cached` prints the saved
// answer without the network, so the window opens at once.

// The service's answer. Only short labels and dates: titles and names stay in
// the web app, behind the person's sign-in.
type dueResponse struct {
	Due struct {
		Audience string        `json:"audience"`
		Days     int           `json:"days"`
		Items    []notify.Item `json:"items"`
	} `json:"due"`
	Required []string `json:"required"`
}

type webFilterOutput struct {
	Required bool              `json:"required"`
	Status   *webfilter.Status `json:"status,omitempty"`
}

type dueOutput struct {
	Paired       bool             `json:"paired"`
	Available    bool             `json:"available"`
	Audience     string           `json:"audience,omitempty"`
	Days         int              `json:"days,omitempty"`
	Items        []notify.Item    `json:"items"`
	Required     []string         `json:"required"`
	WebFiltering *webFilterOutput `json:"web_filtering,omitempty"`
	FetchedAt    *time.Time       `json:"fetched_at,omitempty"`
	// Stale is set when the service could not be reached and this is the
	// last saved answer.
	Stale  bool           `json:"stale,omitempty"`
	Error  string         `json:"error,omitempty"`
	Notify *notify.Result `json:"notify,omitempty"`
}

func dueCachePath(dir string) string { return filepath.Join(dir, "due.json") }

func dueURL(reportURL string) string {
	return strings.TrimSuffix(reportURL, "/reports") + "/due"
}

const requiredWebFiltering = "web_filtering"

func dueCommand(args []string) {
	flags := flag.NewFlagSet("due", flag.ExitOnError)
	cached := flags.Bool("cached", false, "print the last saved answer, without the network")
	_ = flags.Parse(args)
	dir := stateDir()
	state, err := loadStateFrom(dir)
	if err != nil {
		printJSON(dueOutput{Paired: false, Items: []notify.Item{}, Required: []string{}})
		return
	}
	if *cached {
		out, ok := loadDueCache(dir)
		if !ok {
			out = dueOutput{Paired: true, Items: []notify.Item{}, Required: []string{}}
		}
		printJSON(out)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out := dueOutput{Paired: true, Items: []notify.Item{}, Required: []string{}}
	response, fetchErr := fetchDue(ctx, state, time.Now())
	if fetchErr != nil {
		saved, ok := loadDueCache(dir)
		if ok {
			out = saved
			out.Stale = true
		}
		out.Error = "We couldn't reach Compliance Everywhere to update your dates."
	} else {
		now := time.Now().UTC()
		out.Available = true
		out.FetchedAt = &now
		out.Audience = response.Due.Audience
		if out.Audience != "you" {
			out.Audience = "company"
		}
		out.Days = response.Due.Days
		out.Items = sanitizeItems(response.Due.Items)
		out.Required = sanitizeRequired(response.Required)
	}
	// Web filtering is checked only on a computer whose workspace asks for it
	// (ISO 27001 on): the check looks up a malware test domain, which nobody
	// else should see this computer do.
	out.WebFiltering = &webFilterOutput{Required: contains(out.Required, requiredWebFiltering)}
	if out.WebFiltering.Required {
		status := webfilter.Check(ctx)
		out.WebFiltering.Status = &status
		if tell, err := webfilter.Watch(dir, status); err == nil && tell {
			notify.Alert("Web filtering is off on this laptop", "Its DNS no longer blocks malware sites. Open Compliance Agent to turn it back on.")
		}
	}
	if fetchErr == nil {
		if err := saveDueCache(dir, out); err != nil {
			fmt.Fprintln(os.Stderr, "device-checker: could not save the dates:", err)
		}
		// New and late tasks are told only from a fresh answer, never from
		// the saved one.
		result, err := notify.Process(dir, out.Items)
		if err != nil {
			fmt.Fprintln(os.Stderr, "device-checker: could not record the tasks:", err)
		} else {
			out.Notify = &result
		}
	}
	printJSON(out)
}

// fetchDue signs a short request with this device's key. The field order is
// the signed message contract; the service verifies exactly these five fields.
func fetchDue(ctx context.Context, state savedState, now time.Time) (dueResponse, error) {
	unsigned := struct {
		SchemaVersion int    `json:"schema_version"`
		Kind          string `json:"kind"`
		DeviceID      string `json:"device_id"`
		PublicKey     string `json:"public_key"`
		CreatedAt     string `json:"created_at"`
	}{1, "due", state.Identity.ID, state.Identity.PublicKey, now.UTC().Format(time.RFC3339)}
	message, err := json.Marshal(unsigned)
	if err != nil {
		return dueResponse{}, err
	}
	signature, err := state.Identity.Sign(message)
	if err != nil {
		return dueResponse{}, err
	}
	body := map[string]any{
		"schema_version": unsigned.SchemaVersion,
		"kind":           unsigned.Kind,
		"device_id":      unsigned.DeviceID,
		"public_key":     unsigned.PublicKey,
		"created_at":     unsigned.CreatedAt,
		"signature":      signature,
	}
	var response dueResponse
	if _, err := postJSONStatus(ctx, dueURL(state.ReportURL), body, &response); err != nil {
		return dueResponse{}, err
	}
	return response, nil
}

var (
	dueGroups   = map[string]bool{"security": true, "risks": true, "iso27001": true, "soc2": true}
	dueTabs     = map[string]bool{"nonconformities": true, "risks": true, "objectives": true}
	dueDate     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	dueControl  = regexp.MustCompile(`^[A-Z]{2,6}-\d{1,3}$`)
	maxDueItems = 100
)

// sanitizeItems keeps only well-formed items with short, plain text. The
// service is trusted for the list, never for markup or links.
func sanitizeItems(items []notify.Item) []notify.Item {
	out := make([]notify.Item, 0, len(items))
	for _, item := range items {
		if len(out) >= maxDueItems {
			break
		}
		clean := notify.Item{
			Group: item.Group,
			Label: plainText(item.Label, 40),
			What:  plainText(item.What, 60),
			Due:   item.Due,
			Days:  item.Days,
		}
		if !dueGroups[clean.Group] || clean.Label == "" || !dueDate.MatchString(clean.Due) {
			continue
		}
		if dueTabs[item.Tab] {
			clean.Tab = item.Tab
		}
		if dueControl.MatchString(item.ControlID) {
			clean.ControlID = item.ControlID
		}
		out = append(out, clean)
	}
	return out
}

func sanitizeRequired(required []string) []string {
	out := []string{}
	for _, r := range required {
		if r == requiredWebFiltering && !contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}

// plainText keeps printable characters only, without markup, and caps length.
func plainText(text string, limit int) string {
	var b strings.Builder
	count := 0
	for _, r := range text {
		if count >= limit {
			break
		}
		if r < 0x20 || r == 0x7f || r == '<' || r == '>' || r == '&' {
			continue
		}
		b.WriteRune(r)
		count++
	}
	return strings.TrimSpace(b.String())
}

func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

func loadDueCache(dir string) (dueOutput, bool) {
	data, err := os.ReadFile(dueCachePath(dir))
	if err != nil {
		return dueOutput{}, false
	}
	var out dueOutput
	if json.Unmarshal(data, &out) != nil {
		return dueOutput{}, false
	}
	out.Paired = true
	out.Notify = nil
	out.Items = sanitizeItems(out.Items)
	out.Required = sanitizeRequired(out.Required)
	return out, true
}

func saveDueCache(dir string, out dueOutput) error {
	out.Notify = nil
	data, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	temporary := dueCachePath(dir) + ".tmp"
	if err := os.WriteFile(temporary, data, 0600); err != nil {
		return err
	}
	return os.Rename(temporary, dueCachePath(dir))
}

// ---------------------------------------------------------------- web filtering

// webFilterCommand: `webfilter status|plan|on|off`. on and off run only
// because the person pressed the button in the window.
func webFilterCommand(args []string) {
	if len(args) != 1 {
		fatal(errors.New("webfilter takes status, plan, on or off"))
	}
	dir := stateDir()
	switch args[0] {
	case "status":
		printJSON(webfilter.Check(context.Background()))
	case "plan":
		printJSON(webfilter.PlanFor(dir))
	case "on", "off":
		requireElevation()
		var err error
		if args[0] == "on" {
			err = webfilter.TurnOn(dir)
		} else {
			err = webfilter.TurnOff(dir)
		}
		if err != nil {
			failJSON("webfilter_failed", err.Error(), 1)
		}
		// The new DNS needs a moment before the check sees it: the first
		// encrypted (DNS over HTTPS) lookup opens a connection, and until it
		// answers a check reads "unknown" (found by the webfilter-windows CI
		// job, 23 Nov 2026). Ask again for up to about 20 seconds.
		status := webfilter.Status{State: webfilter.StateUnknown}
		for start := time.Now(); time.Since(start) < 20*time.Second; {
			time.Sleep(time.Second)
			status = webfilter.Check(context.Background())
			if (args[0] == "on" && status.State == webfilter.StateOn) || (args[0] == "off" && status.State != webfilter.StateUnknown) {
				break
			}
		}
		if args[0] == "on" {
			_, _ = webfilter.Watch(dir, status)
		}
		printJSON(map[string]any{"ok": true, "status": status, "plan": webfilter.PlanFor(dir)})
	default:
		fatal(errors.New("webfilter takes status, plan, on or off"))
	}
}

// ---------------------------------------------------------------- updates

var releaseVersion = regexp.MustCompile(`^\d{1,4}\.\d{1,4}\.\d{1,6}$`)

// notifyUpdate shows the one reminder that an update is waiting, a day after
// the person chose "Remind me tomorrow". The window decides when.
func notifyUpdate(args []string) {
	flags := flag.NewFlagSet("notify-update", flag.ExitOnError)
	version := flags.String("version", "", "the waiting version")
	_ = flags.Parse(args)
	if !releaseVersion.MatchString(*version) {
		fatal(errors.New("notify-update needs --version like 0.2.0"))
	}
	printJSON(notify.Alert("Compliance Agent "+*version+" is ready", "Open Compliance Agent to install it. It takes about a minute."))
}
