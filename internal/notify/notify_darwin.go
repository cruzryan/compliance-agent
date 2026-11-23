//go:build darwin

package notify

import "os/exec"

// Status: macOS has no command that reports whether a helper may notify.
func Status() string { return SystemUnknown }

// Show uses the system's own AppleScript notification. The text is passed as
// arguments to the script, never spliced into it.
func Show(title, body string) error {
	script := `on run argv
display notification (item 2 of argv) with title (item 1 of argv)
end run`
	return exec.Command("osascript", "-e", script, title, body).Run()
}

// Attention on macOS is the Dock bounce, which the tray app does; nothing here.
func Attention() error { return nil }
