package notify

import (
	"strings"
	"testing"
)

type calls struct{ shown, flashed int }

func fake(t *testing.T, system string) *calls {
	t.Helper()
	c := &calls{}
	oldStatus, oldShow, oldAttention := statusFn, showFn, attentionFn
	statusFn = func() string { return system }
	showFn = func(title, body string) error { c.shown++; return nil }
	attentionFn = func() error { c.flashed++; return nil }
	t.Cleanup(func() { statusFn, showFn, attentionFn = oldStatus, oldShow, oldAttention })
	return c
}

var base = []Item{
	{Group: "iso27001", Label: "NC-02", What: "Fix due", Due: "2026-11-21", Days: -1},
	{Group: "risks", Label: "R-19", What: "Fix plan due", Due: "2026-11-18", Days: -4},
}

func TestFirstRunRecordsEverythingAndTellsNothing(t *testing.T) {
	c := fake(t, SystemOn)
	dir := t.TempDir()
	result, err := Process(dir, base)
	if err != nil {
		t.Fatal(err)
	}
	if !result.FirstRun || len(result.New) != 0 || c.shown != 0 || c.flashed != 0 {
		t.Fatalf("first run must be silent: %+v %+v", result, c)
	}
}

func TestANewTaskIsToldOnceEver(t *testing.T) {
	c := fake(t, SystemOn)
	dir := t.TempDir()
	if _, err := Process(dir, base); err != nil {
		t.Fatal(err)
	}
	withNew := append(append([]Item(nil), base...), Item{Group: "iso27001", Label: "NC-28", What: "Reply to the auditor due", Due: "2026-11-28", Days: 6})
	result, _ := Process(dir, withNew)
	if len(result.New) != 1 || result.New[0].Label != "NC-28" || c.shown != 1 || c.flashed != 1 {
		t.Fatalf("NC-28 must be told once: %+v %+v", result, c)
	}
	// The same list again, and again: nothing more.
	for i := 0; i < 3; i++ {
		result, _ = Process(dir, withNew)
		if len(result.New) != 0 {
			t.Fatalf("told again on run %d: %+v", i, result)
		}
	}
	if c.shown != 1 || c.flashed != 1 {
		t.Fatalf("repeated: %+v", c)
	}
}

func TestAMovedDeadlineIsNotANewTask(t *testing.T) {
	c := fake(t, SystemOn)
	dir := t.TempDir()
	Process(dir, base)
	moved := append([]Item(nil), base...)
	moved[0].Due, moved[0].Days = "2026-12-05", 13
	result, _ := Process(dir, moved)
	if len(result.New) != 0 || c.shown != 0 {
		t.Fatalf("a moved date was treated as new: %+v", result)
	}
}

func TestATaskThatLeavesAndComesBackIsNotToldAgain(t *testing.T) {
	c := fake(t, SystemOn)
	dir := t.TempDir()
	Process(dir, base)
	Process(dir, append(append([]Item(nil), base...), Item{Group: "iso27001", Label: "NC-28", What: "x", Days: 6}))
	Process(dir, base)
	result, _ := Process(dir, append(append([]Item(nil), base...), Item{Group: "iso27001", Label: "NC-28", What: "x", Days: 6}))
	if len(result.New) != 0 || c.shown != 1 {
		t.Fatalf("NC-28 came back and was told again: %+v %+v", result, c)
	}
}

func TestTheSwitchOffTellsNothingButStillRemembers(t *testing.T) {
	c := fake(t, SystemOn)
	dir := t.TempDir()
	Process(dir, base)
	if err := SaveSettings(dir, Settings{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	next := append(append([]Item(nil), base...), Item{Group: "soc2", Label: "CM-03", What: "Evidence renewal", Days: 30})
	Process(dir, next)
	if c.shown != 0 || c.flashed != 0 {
		t.Fatalf("switch off still told: %+v", c)
	}
	// Turned back on later: CM-03 is old news, not a new task.
	SaveSettings(dir, Settings{Enabled: true})
	result, _ := Process(dir, next)
	if len(result.New) != 0 || c.shown != 0 {
		t.Fatalf("turning the switch on replayed old tasks: %+v", result)
	}
}

func TestNoNotificationWhenTheSystemSaysOffButTheTaskbarStillLightsUp(t *testing.T) {
	c := fake(t, SystemOffByUser)
	dir := t.TempDir()
	Process(dir, base)
	result, _ := Process(dir, append(append([]Item(nil), base...), Item{Group: "iso27001", Label: "NC-28", What: "x", Days: 6}))
	if c.shown != 0 || c.flashed != 1 || result.System != SystemOffByUser {
		t.Fatalf("expected no notification, one flash: %+v %+v", result, c)
	}
}

func TestTheMessageLeadsWithTheMostUrgentAndCleansLabels(t *testing.T) {
	title, body := Message([]Item{
		{Label: "NC-28", What: "Reply due", Days: 6},
		{Label: "R-<b>19</b>", What: "Fix plan due", Days: -2},
	})
	if title != "2 new tasks in Compliance Agent" {
		t.Fatal(title)
	}
	if !strings.HasPrefix(body, "R-b19/b · Fix plan due, 2 days late") || !strings.HasSuffix(body, "and 1 more") {
		t.Fatal(body)
	}
}

func TestATaskThatBecomesLateIsToldOnceAsLate(t *testing.T) {
	c := fake(t, SystemOn)
	dir := t.TempDir()
	soon := Item{Group: "iso27001", Label: "NC-28", What: "Reply to the auditor", Due: "2026-11-28", Days: 1}
	Process(dir, append(append([]Item(nil), base...), soon))
	late := soon
	late.Days = -1
	result, _ := Process(dir, append(append([]Item(nil), base...), late))
	if len(result.Late) != 1 || result.Late[0].Label != "NC-28" || len(result.New) != 0 || c.shown != 1 {
		t.Fatalf("NC-28 becoming late must be told once: %+v %+v", result, c)
	}
	for i := 0; i < 3; i++ {
		late.Days--
		result, _ = Process(dir, append(append([]Item(nil), base...), late))
		if len(result.Late) != 0 {
			t.Fatalf("late told again on run %d: %+v", i, result)
		}
	}
	if c.shown != 1 {
		t.Fatalf("repeated: %+v", c)
	}
}

func TestTasksAlreadyLateOnTheFirstRunAreNotToldLate(t *testing.T) {
	c := fake(t, SystemOn)
	dir := t.TempDir()
	Process(dir, base)
	result, _ := Process(dir, base)
	if len(result.Late) != 0 || c.shown != 0 {
		t.Fatalf("a late task from the first run was told: %+v %+v", result, c)
	}
}

func TestANewTaskThatIsAlreadyLateIsToldOnceAsNew(t *testing.T) {
	c := fake(t, SystemOn)
	dir := t.TempDir()
	Process(dir, base)
	result, _ := Process(dir, append(append([]Item(nil), base...), Item{Group: "risks", Label: "R-30", What: "Fix plan due", Days: -2}))
	if len(result.New) != 1 || len(result.Late) != 0 || c.shown != 1 {
		t.Fatalf("expected one notification as new: %+v %+v", result, c)
	}
	result, _ = Process(dir, append(append([]Item(nil), base...), Item{Group: "risks", Label: "R-30", What: "Fix plan due", Days: -3}))
	if len(result.New) != 0 || len(result.Late) != 0 || c.shown != 1 {
		t.Fatalf("R-30 was told twice: %+v %+v", result, c)
	}
}

func TestTheSwitchOffAlsoSilencesLateTasks(t *testing.T) {
	c := fake(t, SystemOn)
	dir := t.TempDir()
	soon := Item{Group: "soc2", Label: "CM-03", What: "Evidence renewal", Days: 1}
	Process(dir, []Item{soon})
	SaveSettings(dir, Settings{Enabled: false})
	soon.Days = -1
	result, _ := Process(dir, []Item{soon})
	if len(result.Late) != 1 || c.shown != 0 || c.flashed != 0 {
		t.Fatalf("switch off still told a late task: %+v %+v", result, c)
	}
}

func TestAlertIgnoresTheSwitchButNotTheSystem(t *testing.T) {
	c := fake(t, SystemOn)
	result := Alert("Web filtering is off on this laptop", "Open Compliance Agent to turn it back on.")
	if !result.Shown || c.shown != 1 {
		t.Fatalf("alert not shown: %+v", result)
	}
	c = fake(t, SystemOffByPolicy)
	result = Alert("x", "y")
	if result.Shown || c.shown != 0 {
		t.Fatalf("alert shown although the system turned notifications off: %+v", result)
	}
}

func TestLateMessage(t *testing.T) {
	title, body := LateMessage([]Item{{Label: "NC-02", What: "Fix due", Days: -1}, {Label: "R-19", What: "Fix plan due", Days: -4}})
	if title != "2 tasks are now late" || !strings.HasPrefix(body, "R-19 · Fix plan due, 4 days late") {
		t.Fatal(title, body)
	}
}
