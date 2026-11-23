//go:build !windows && !darwin && !linux

package webfilter

import "errors"

func planOS() Plan { return Plan{Supported: false, Method: "manual", Prompt: "password"} }

func currentServers() ([]byte, error) {
	return nil, errors.New("web filtering is not supported on this system")
}

func applyFilter() error { return errors.New("web filtering is not supported on this system") }

func restoreServers([]byte) error {
	return errors.New("web filtering is not supported on this system")
}
