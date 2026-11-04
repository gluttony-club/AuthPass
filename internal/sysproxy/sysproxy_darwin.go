//go:build darwin

package sysproxy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type state struct {
	Service string
	URL     string
	Enabled bool
}

func run(args ...string) (string, error) {
	b, e := exec.Command("networksetup", args...).CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("networksetup %v: %w: %s", args, e, b)
	}
	return string(b), nil
}
func Restore(dir string) error {
	p := filepath.Join(dir, "proxy-state.json")
	b, e := os.ReadFile(p)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var states []state
	if e = json.Unmarshal(b, &states); e != nil {
		return e
	}
	var errs []string
	for _, s := range states {
		// networksetup rejects an empty URL, so only restore a URL that existed.
		if s.URL != "" {
			if _, e = run("-setautoproxyurl", s.Service, s.URL); e != nil {
				errs = append(errs, e.Error())
				continue
			}
		}
		v := "off"
		if s.Enabled {
			v = "on"
		}
		if _, e = run("-setautoproxystate", s.Service, v); e != nil {
			errs = append(errs, e.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("restore: %s", strings.Join(errs, "; "))
	}
	return os.Remove(p)
}
func Enable(dir, url string) error {
	if e := Restore(dir); e != nil {
		return e
	}
	out, e := run("-listallnetworkservices")
	if e != nil {
		return e
	}
	var states []state
	for i, line := range strings.Split(out, "\n") {
		svc := strings.TrimSpace(line)
		if i == 0 || svc == "" || strings.HasPrefix(svc, "*") || strings.Contains(svc, "denotes") {
			continue
		}
		v, e := run("-getautoproxyurl", svc)
		if e != nil {
			return e
		}
		s := state{Service: svc}
		for _, l := range strings.Split(v, "\n") {
			if strings.HasPrefix(l, "URL: ") {
				s.URL = strings.TrimPrefix(l, "URL: ")
				if s.URL == "(null)" {
					s.URL = ""
				}
			}
			if strings.TrimSpace(l) == "Enabled: Yes" {
				s.Enabled = true
			}
		}
		states = append(states, s)
	}
	b, e := json.MarshalIndent(states, "", "  ")
	if e != nil {
		return e
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	p := filepath.Join(dir, "proxy-state.json")
	if e = os.WriteFile(p+".tmp", b, 0600); e != nil {
		return e
	}
	if e = os.Rename(p+".tmp", p); e != nil {
		return e
	}
	for _, s := range states {
		if _, e = run("-setautoproxyurl", s.Service, fmt.Sprintf("%s?t=%d", url, time.Now().UnixNano())); e == nil {
			_, e = run("-setautoproxystate", s.Service, "on")
		}
		if e != nil {
			restoreErr := Restore(dir)
			return fmt.Errorf("enable: %w; restore: %v", e, restoreErr)
		}
	}
	return nil
}
