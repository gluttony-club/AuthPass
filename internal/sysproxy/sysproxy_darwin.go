//go:build darwin

package sysproxy

import (
	"fmt"
	"os/exec"
	"time"
)

func networksetup(args ...string) (string, error) {
	b, e := exec.Command("networksetup", args...).CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("networksetup %v: %w: %s", args, e, b)
	}
	return string(b), nil
}

// Restore puts back the auto-proxy settings saved by Enable, for services
// whose auto-proxy URL is still AuthPass's.
func Restore(dir string) error { return restore(dir, networksetup) }

// Enable points every network service's auto-proxy URL at url.
func Enable(dir, url string) error {
	return enable(dir, url, networksetup, func() int64 { return time.Now().UnixNano() })
}
