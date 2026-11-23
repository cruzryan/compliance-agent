package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hackzero/device-checker/internal/identity"
	"github.com/hackzero/device-checker/internal/notify"
)

func TestDueURLSitsNextToTheReportURL(t *testing.T) {
	got := dueURL("https://app.complianceeverywhere.com/api/trust/device-checker/reports")
	if got != "https://app.complianceeverywhere.com/api/trust/device-checker/due" {
		t.Fatal(got)
	}
}

// The service verifies exactly these five fields, in this order, as compact
// JSON. A change here breaks every agent's dates.
func TestDueRequestIsSignedOverTheContractFields(t *testing.T) {
	device, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/trust/device-checker/due" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&received)
		_, _ = w.Write([]byte(`{"due":{"audience":"company","days":30,"items":[{"group":"iso27001","label":"NC-28","what":"Reply to the auditor","due":"2026-11-28","days":6,"tab":"nonconformities"}]},"required":["web_filtering"]}`))
	}))
	defer server.Close()
	state := savedState{Identity: device, ReportURL: server.URL + "/api/trust/device-checker/reports"}
	at := time.Date(2026, 11, 22, 23, 10, 0, 0, time.UTC)
	response, err := fetchDue(context.Background(), state, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Due.Items) != 1 || response.Due.Items[0].Label != "NC-28" || response.Required[0] != "web_filtering" {
		t.Fatalf("unexpected response: %+v", response)
	}
	message := `{"schema_version":1,"kind":"due","device_id":"` + device.ID + `","public_key":"` + device.PublicKey + `","created_at":"2026-11-22T23:10:00Z"}`
	signature, _ := received["signature"].(string)
	if !device.Verify([]byte(message), signature) {
		t.Fatalf("signature does not cover the contract message %s", message)
	}
	if received["kind"] != "due" || received["created_at"] != "2026-11-22T23:10:00Z" {
		t.Fatalf("unexpected body: %v", received)
	}
}

func TestSanitizeItemsDropsAnythingMalformed(t *testing.T) {
	items := sanitizeItems([]notify.Item{
		{Group: "iso27001", Label: "NC-28", What: "Reply to the auditor", Due: "2026-11-28", Days: 6, Tab: "nonconformities"},
		{Group: "soc2", Label: "CM-03", What: "Evidence renewal", Due: "2026-12-22", Days: 30, ControlID: "CM-03"},
		{Group: "evil", Label: "X", Due: "2026-11-28"},
		{Group: "risks", Label: "", Due: "2026-11-28"},
		{Group: "risks", Label: "R-19", Due: "next week"},
		{Group: "risks", Label: "R-<script>1</script>", What: "Fix plan due", Due: "2026-11-18", Days: -4, Tab: "javascript:alert(1)", ControlID: "../x"},
	})
	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %+v", items)
	}
	if items[2].Label != "R-script1/script" || items[2].Tab != "" || items[2].ControlID != "" {
		t.Fatalf("not cleaned: %+v", items[2])
	}
	if items[1].ControlID != "CM-03" || items[0].Tab != "nonconformities" {
		t.Fatalf("lost a valid link: %+v", items)
	}
}

func TestSanitizeRequiredKeepsKnownValuesOnly(t *testing.T) {
	got := sanitizeRequired([]string{"web_filtering", "rm -rf", "web_filtering"})
	if len(got) != 1 || got[0] != "web_filtering" {
		t.Fatal(got)
	}
}

func TestTheDueCacheRoundTrips(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	out := dueOutput{Paired: true, Available: true, Audience: "company", Days: 30, FetchedAt: &now,
		Items:    []notify.Item{{Group: "risks", Label: "R-19", What: "Fix plan due", Due: "2026-11-18", Days: -4, Tab: "risks"}},
		Required: []string{"web_filtering"}, Notify: &notify.Result{Shown: true}}
	if err := saveDueCache(dir, out); err != nil {
		t.Fatal(err)
	}
	got, ok := loadDueCache(dir)
	if !ok || len(got.Items) != 1 || got.Notify != nil || got.Required[0] != "web_filtering" {
		t.Fatalf("cache did not round-trip: %+v", got)
	}
}
