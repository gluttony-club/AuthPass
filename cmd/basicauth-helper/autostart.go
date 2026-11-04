package main

import (
	"basicauth-helper/internal/autostart"
	"basicauth-helper/internal/settings"
)

// Register platform operations outside the HTTP settings manager.
func initializeLaunchAtLogin(m *settings.Manager) error {
	agent, initErr := autostart.New()
	m.SetLaunchAtLogin = func(v bool) error {
		if initErr != nil {
			return initErr
		}
		if !v {
			return agent.Disable()
		}
		enabled, err := agent.Status()
		if err == nil && enabled {
			return nil
		}
		// A stale path or missing plist is repaired at startup.
		return agent.Enable()
	}
	return m.UpdateLaunchAtLogin(m.LaunchAtLogin())
}
