//go:build !darwin

package autostart

// Agent accepts explicit paths for tests; outside macOS it only records state in memory.
type Agent struct {
	Home, Executable string
	enabled          bool
}

func (a *Agent) Enable() error         { a.enabled = true; return nil }
func (a *Agent) Disable() error        { a.enabled = false; return nil }
func (a *Agent) Status() (bool, error) { return a.enabled, nil }
