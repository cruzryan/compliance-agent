//go:build !windows && !darwin && !linux

package notify

import "errors"

func Status() string { return SystemUnknown }
func Show(title, body string) error {
	return errors.New("notifications are not supported on this system")
}
func Attention() error { return nil }
