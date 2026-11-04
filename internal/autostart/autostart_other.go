//go:build !darwin

package autostart

func (a *Agent) Enable() error         { a.enabled = true; return nil }
func (a *Agent) Disable() error        { a.enabled = false; return nil }
func (a *Agent) Status() (bool, error) { return a.enabled, nil }
