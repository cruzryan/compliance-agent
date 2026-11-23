//go:build linux

package notify

import (
	"errors"
	"os/exec"
)

// Status reports whether a desktop notification service can be reached.
// Linux has no per-app notification permission.
func Status() string {
	if _, err := exec.LookPath("notify-send"); err == nil {
		return SystemOn
	}
	if exec.Command("gdbus", "introspect", "--session", "--dest", "org.freedesktop.Notifications",
		"--object-path", "/org/freedesktop/Notifications").Run() == nil {
		return SystemOn
	}
	return SystemUnknown
}

// Show uses notify-send, or the freedesktop notification service through
// gdbus. Text goes as arguments, never through a shell.
func Show(title, body string) error {
	if _, err := exec.LookPath("notify-send"); err == nil {
		return exec.Command("notify-send", "--app-name=Compliance Agent", title, body).Run()
	}
	if _, err := exec.LookPath("gdbus"); err != nil {
		return errors.New("no notification service found")
	}
	return exec.Command("gdbus", "call", "--session", "--dest", "org.freedesktop.Notifications",
		"--object-path", "/org/freedesktop/Notifications", "--method", "org.freedesktop.Notifications.Notify",
		"Compliance Agent", "0", "", title, body, "[]", "{}", "-1").Run()
}

// Attention on Linux is the window urgency hint, which the tray app sets.
func Attention() error { return nil }
