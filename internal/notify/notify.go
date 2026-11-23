// Package notify tells the person about a NEW task, and about a task that
// just became LATE: once per task for each, ever, on this computer, with the
// operating system's own notifications and taskbar attention. It uses only the
// standard library and tools every supported system already has (PowerShell
// on Windows, osascript on macOS, notify-send or gdbus on Linux).
//
// What counts as new: a task (group + label, never its date) this computer
// has not seen before. What counts as late: a task whose date passed that
// this computer has not yet told as late. Both lists are written to disk
// BEFORE any notification is shown, so a crash, a restart or a second run can
// never show the same notification again. The first run ever records
// everything and notifies nothing, so installing the agent never fires a burst.
//
// The one switch ("Notify me about new tasks") covers these task
// notifications. Alert is for the few messages that are not about tasks (web
// filtering turned off, an update waiting) and is not covered by the switch.
package notify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Item is one dated task as the service sends it: short labels only. Tab and
// ControlID only say which page of the web app opens it.
type Item struct {
	Group     string `json:"group"`
	Label     string `json:"label"`
	What      string `json:"what"`
	Due       string `json:"due"`
	Days      int    `json:"days"`
	Tab       string `json:"tab,omitempty"`
	ControlID string `json:"control_id,omitempty"`
}

// Key is what makes a task the same task: a moved deadline is not a new task.
func (i Item) Key() string { return i.Group + "|" + i.Label }

// Settings is the one switch, "Notify me about new tasks".
type Settings struct {
	Enabled bool `json:"enabled"`
}

// System notification states, as Status reports them.
const (
	SystemOn          = "on"
	SystemOffByUser   = "off_by_user"
	SystemOffByPolicy = "off_by_policy"
	SystemUnknown     = "unknown"
)

// The system calls, swapped out by tests so a test never shows anything.
var (
	statusFn    = Status
	showFn      = Show
	attentionFn = Attention
)

// maxKnown bounds the remembered tasks; the oldest are dropped first.
const maxKnown = 2000

type store struct {
	Initialized bool     `json:"initialized"`
	Known       []string `json:"known"`
	// Late is every task already told (or recorded on the first run) as late.
	Late []string `json:"late,omitempty"`
}

func settingsPath(dir string) string { return filepath.Join(dir, "notify-settings.json") }
func storePath(dir string) string    { return filepath.Join(dir, "notified.json") }

// LoadSettings reads the switch. Missing or unreadable means on.
func LoadSettings(dir string) Settings {
	data, err := os.ReadFile(settingsPath(dir))
	if err != nil {
		return Settings{Enabled: true}
	}
	var s Settings
	if json.Unmarshal(data, &s) != nil {
		return Settings{Enabled: true}
	}
	return s
}

// SaveSettings writes the switch.
func SaveSettings(dir string, s Settings) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return writeFileAtomic(settingsPath(dir), data)
}

func loadStore(dir string) store {
	data, err := os.ReadFile(storePath(dir))
	if err != nil {
		return store{}
	}
	var s store
	if json.Unmarshal(data, &s) != nil {
		// A corrupt file must not turn every task into a new one: start over
		// as a first run (record, do not notify).
		return store{}
	}
	return s
}

// Result is what one Process call did.
type Result struct {
	FirstRun bool   `json:"first_run"`
	New      []Item `json:"new"`
	Late     []Item `json:"late"`
	Enabled  bool   `json:"enabled"`
	System   string `json:"system,omitempty"`
	Shown    bool   `json:"shown"`
	Flashed  bool   `json:"flashed"`
	Error    string `json:"error,omitempty"`
}

// Process records the current tasks and tells the person about the new ones
// and the ones that just became late, in one notification at most.
func Process(dir string, items []Item) (Result, error) {
	settings := LoadSettings(dir)
	result := Result{Enabled: settings.Enabled}
	st := loadStore(dir)
	known := make(map[string]bool, len(st.Known))
	for _, key := range st.Known {
		known[key] = true
	}
	toldLate := make(map[string]bool, len(st.Late))
	for _, key := range st.Late {
		toldLate[key] = true
	}
	var fresh, late []Item
	for _, item := range items {
		if item.Label == "" {
			continue
		}
		key := item.Key()
		isNew := !known[key]
		if isNew {
			known[key] = true
			st.Known = append(st.Known, key)
			fresh = append(fresh, item)
		}
		if item.Days < 0 && !toldLate[key] {
			toldLate[key] = true
			st.Late = append(st.Late, key)
			// A task that arrives already late is told once, as new.
			if !isNew {
				late = append(late, item)
			}
		}
	}
	if len(st.Known) > maxKnown {
		st.Known = st.Known[len(st.Known)-maxKnown:]
	}
	if len(st.Late) > maxKnown {
		st.Late = st.Late[len(st.Late)-maxKnown:]
	}
	if !st.Initialized {
		st.Initialized = true
		result.FirstRun = true
		fresh, late = nil, nil
	}
	// Remember first. Only then tell: a failure after this line can lose a
	// notification, never repeat one.
	data, err := json.Marshal(st)
	if err != nil {
		return result, err
	}
	if err := writeFileAtomic(storePath(dir), data); err != nil {
		return result, err
	}
	result.New, result.Late = fresh, late
	if (len(fresh) == 0 && len(late) == 0) || !settings.Enabled {
		return result, nil
	}
	var title, body string
	if len(fresh) > 0 {
		title, body = Message(fresh)
		if len(late) == 1 {
			body += ". 1 task is now late"
		} else if len(late) > 1 {
			body += fmt.Sprintf(". %d tasks are now late", len(late))
		}
	} else {
		title, body = LateMessage(late)
	}
	result.System, result.Shown, result.Flashed, result.Error = tell(title, body)
	return result, nil
}

// Alert shows one notification that is not about a task (web filtering was
// turned off, an update is waiting). The switch does not cover it; the
// system's own setting still does. The caller makes sure it is shown once.
func Alert(title, body string) Result {
	var result Result
	result.Enabled = true
	result.System, result.Shown, result.Flashed, result.Error = tell(clean(title, 80), clean(body, 200))
	return result
}

// tell shows the notification and lights up the taskbar. Sent when the system
// says on, or has not decided yet (an app that never notified has no setting);
// never when the person or a policy turned it off.
func tell(title, body string) (system string, shown, flashed bool, problem string) {
	system = statusFn()
	if system == SystemOn || system == SystemUnknown {
		if err := showFn(title, body); err != nil {
			problem = err.Error()
		} else {
			shown = true
		}
	}
	if err := attentionFn(); err == nil {
		flashed = true
	} else if problem == "" {
		problem = err.Error()
	}
	return system, shown, flashed, problem
}

// Message is the notification text: the most urgent new task, then a count.
func Message(fresh []Item) (title, body string) {
	sorted := append([]Item(nil), fresh...)
	sort.SliceStable(sorted, func(a, b int) bool { return sorted[a].Days < sorted[b].Days })
	first := sorted[0]
	body = fmt.Sprintf("%s · %s, %s", clean(first.Label, 32), clean(first.What, 40), when(first.Days))
	if len(sorted) > 1 {
		body += fmt.Sprintf(", and %d more", len(sorted)-1)
	}
	title = "New task in Compliance Agent"
	if len(sorted) > 1 {
		title = fmt.Sprintf("%d new tasks in Compliance Agent", len(sorted))
	}
	return title, body
}

// LateMessage is the text for tasks that just became late.
func LateMessage(late []Item) (title, body string) {
	sorted := append([]Item(nil), late...)
	sort.SliceStable(sorted, func(a, b int) bool { return sorted[a].Days < sorted[b].Days })
	first := sorted[0]
	body = fmt.Sprintf("%s · %s, %s", clean(first.Label, 32), clean(first.What, 40), when(first.Days))
	if len(sorted) > 1 {
		body += fmt.Sprintf(", and %d more", len(sorted)-1)
	}
	title = "A task is now late"
	if len(sorted) > 1 {
		title = fmt.Sprintf("%d tasks are now late", len(sorted))
	}
	return title, body
}

func when(days int) string {
	switch {
	case days < -1:
		return fmt.Sprintf("%d days late", -days)
	case days == -1:
		return "1 day late"
	case days == 0:
		return "due today"
	case days == 1:
		return "due tomorrow"
	default:
		return fmt.Sprintf("due in %d days", days)
	}
}

// clean keeps printable text only and caps its length: a label from the
// service is never trusted to carry markup or control characters.
func clean(text string, limit int) string {
	var b strings.Builder
	for _, r := range text {
		if b.Len() >= limit {
			break
		}
		if r >= 0x20 && r != 0x7f && r != '<' && r != '>' && r != '&' {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
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
