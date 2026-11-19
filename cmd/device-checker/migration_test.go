package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeLegacyState(t *testing.T, base string) string {
	t.Helper()
	legacy := filepath.Join(base, "HackZero", "DeviceChecker")
	if err := os.MkdirAll(legacy, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "identity.json"), []byte(`{"id":"device-1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	return legacy
}

func TestResolveStateDirMovesAPairedDeviceToTheNewName(t *testing.T) {
	base := t.TempDir()
	legacy := writeLegacyState(t, base)

	got := resolveStateDir(base, true)

	want := filepath.Join(base, "ComplianceEverywhere", "ComplianceAgent")
	if got != want {
		t.Fatalf("state dir = %q, want %q", got, want)
	}
	if data, err := os.ReadFile(filepath.Join(want, "identity.json")); err != nil || string(data) != `{"id":"device-1"}` {
		t.Fatalf("identity did not move intact: %q, %v", data, err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("old directory still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(legacy)); !os.IsNotExist(err) {
		t.Fatalf("empty old parent still exists: %v", err)
	}
}

func TestResolveStateDirLeavesStateInPlaceForAPreview(t *testing.T) {
	base := t.TempDir()
	legacy := writeLegacyState(t, base)

	if got := resolveStateDir(base, false); got != legacy {
		t.Fatalf("state dir = %q, want the old directory %q", got, legacy)
	}
	if _, err := os.Stat(filepath.Join(legacy, "identity.json")); err != nil {
		t.Fatalf("a preview must not move the installed app's state: %v", err)
	}
}

func TestResolveStateDirPrefersTheNewDirectory(t *testing.T) {
	base := t.TempDir()
	legacy := writeLegacyState(t, base)
	current := filepath.Join(base, "ComplianceEverywhere", "ComplianceAgent")
	if err := os.MkdirAll(current, 0700); err != nil {
		t.Fatal(err)
	}

	if got := resolveStateDir(base, true); got != current {
		t.Fatalf("state dir = %q, want %q", got, current)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("the old directory must be left alone when the new one exists: %v", err)
	}
}

func TestResolveStateDirForAFreshInstall(t *testing.T) {
	base := t.TempDir()
	want := filepath.Join(base, "ComplianceEverywhere", "ComplianceAgent")
	if got := resolveStateDir(base, true); got != want {
		t.Fatalf("state dir = %q, want %q", got, want)
	}
}

func TestCurrentReportURL(t *testing.T) {
	cases := map[string]string{
		"https://dashboard.hackzero.ai/api/trust/device-checker/reports":        "https://app.complianceeverywhere.com/api/trust/device-checker/reports",
		"https://DASHBOARD.hackzero.ai/api/trust/device-checker/reports":        "https://app.complianceeverywhere.com/api/trust/device-checker/reports",
		"https://app.complianceeverywhere.com/api/trust/device-checker/reports": "https://app.complianceeverywhere.com/api/trust/device-checker/reports",
		"http://127.0.0.1:8000/api/trust/device-checker/reports":                "http://127.0.0.1:8000/api/trust/device-checker/reports",
		"https://dashboard.hackzero.ai.example.com/reports":                     "https://dashboard.hackzero.ai.example.com/reports",
	}
	for saved, want := range cases {
		if got := currentReportURL(saved); got != want {
			t.Errorf("currentReportURL(%q) = %q, want %q", saved, got, want)
		}
	}
}
