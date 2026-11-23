//go:build windows

package notify

import (
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// AppID is the installed app's Windows identity (its Start menu entry). A
// notification sent with it shows as Compliance Agent, with its icon.
const AppID = "com.complianceeverywhere.agent"

// The text reaches PowerShell only through environment variables and is XML
// escaped there: nothing from the service is ever part of the script itself.
const toastScript = `
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:CA_APP_ID)
# An app that never notified has no setting yet (reading it throws): that is
# "not decided", not "off". Only an explicit Disabled... stops the notification.
try { $setting = [string]$notifier.Setting } catch { $setting = '' }
if ($env:CA_MODE -eq 'status' -or $setting -like 'Disabled*') { Write-Output $setting; exit 0 }
$title = [System.Security.SecurityElement]::Escape($env:CA_TITLE)
$body = [System.Security.SecurityElement]::Escape($env:CA_BODY)
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$title</text><text>$body</text></binding></visual></toast>")
$notifier.Show([Windows.UI.Notifications.ToastNotification]::new($xml))
Write-Output 'Shown'
`

func runToast(mode, title, body string) (string, error) {
	// -EncodedCommand (UTF-16LE, base64) so no quoting of the script can ever
	// change it on its way to PowerShell.
	units := utf16.Encode([]rune(toastScript))
	raw := make([]byte, 0, len(units)*2)
	for _, u := range units {
		raw = append(raw, byte(u), byte(u>>8))
	}
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw))
	command.Env = append(os.Environ(), "CA_APP_ID="+AppID, "CA_MODE="+mode, "CA_TITLE="+title, "CA_BODY="+body)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := command.Output()
	return strings.TrimSpace(string(output)), err
}

// Status asks Windows whether Compliance Agent may show notifications.
func Status() string {
	setting, err := runToast("status", "", "")
	if err != nil {
		return SystemUnknown
	}
	switch setting {
	case "Enabled":
		return SystemOn
	case "DisabledForApplication", "DisabledForUser":
		return SystemOffByUser
	case "DisabledByGroupPolicy", "DisabledByManifest":
		return SystemOffByPolicy
	default:
		return SystemUnknown
	}
}

// Show displays one notification. Status is checked again inside the script.
func Show(title, body string) error {
	out, err := runToast("show", title, body)
	if err != nil {
		return err
	}
	if out != "Shown" {
		return errors.New("Windows did not show the notification: " + out)
	}
	return nil
}

var (
	user32          = syscall.NewLazyDLL("user32.dll")
	findWindow      = user32.NewProc("FindWindowW")
	isWindowVisible = user32.NewProc("IsWindowVisible")
	showWindow      = user32.NewProc("ShowWindow")
	flashWindowEx   = user32.NewProc("FlashWindowEx")
)

const (
	swShowMinNoActive = 7
	flashwAll         = 0x3
	flashwTimerNoFG   = 0xC
)

type flashInfo struct {
	size    uint32
	window  uintptr
	flags   uint32
	count   uint32
	timeout uint32
}

// Attention lights up Compliance Agent in the taskbar until the person opens
// it. Closed to the tray, the window has no taskbar button, so it is first
// put back in the taskbar, minimized and without taking focus.
func Attention() error {
	title, err := syscall.UTF16PtrFromString("Compliance Agent")
	if err != nil {
		return err
	}
	window, _, _ := findWindow.Call(0, uintptr(unsafe.Pointer(title)))
	if window == 0 {
		return errors.New("the Compliance Agent window is not open")
	}
	if visible, _, _ := isWindowVisible.Call(window); visible == 0 {
		showWindow.Call(window, swShowMinNoActive)
	}
	info := flashInfo{window: window, flags: flashwAll | flashwTimerNoFG}
	info.size = uint32(unsafe.Sizeof(info))
	flashWindowEx.Call(uintptr(unsafe.Pointer(&info)))
	return nil
}
