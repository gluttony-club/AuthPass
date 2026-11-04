package autostart

import (
	"os"
)

func (a *Agent) Enable() error { return a.write() }

// Removing only the file avoids killing our own launchd-managed process.
func (a *Agent) Disable() error {
	err := os.Remove(a.Path())
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
func (a *Agent) Status() (bool, error) {
	if err := ValidatePath(a.Executable); err != nil {
		return false, err
	}
	b, err := os.ReadFile(a.Path())
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return PointsAt(b, a.Executable), nil
}
