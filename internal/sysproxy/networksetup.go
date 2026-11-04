package sysproxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// runner runs networksetup with the given arguments and returns its output.
type runner func(args ...string) (string, error)

// state is the auto-proxy setting of one network service before AuthPass
// changed it, plus the URL AuthPass set (Applied).
type state struct {
	Service string
	URL     string
	Enabled bool
	Applied string `json:",omitempty"`
}

func services(run runner) ([]string, error) {
	out, e := run("-listallnetworkservices")
	if e != nil {
		return nil, e
	}
	var list []string
	for i, line := range strings.Split(out, "\n") {
		svc := strings.TrimSpace(line)
		if i == 0 || svc == "" || strings.HasPrefix(svc, "*") || strings.Contains(svc, "denotes") {
			continue
		}
		list = append(list, svc)
	}
	return list, nil
}

func autoproxy(run runner, svc string) (url string, enabled bool, err error) {
	v, e := run("-getautoproxyurl", svc)
	if e != nil {
		return "", false, e
	}
	for _, l := range strings.Split(v, "\n") {
		if strings.HasPrefix(l, "URL: ") {
			url = strings.TrimPrefix(l, "URL: ")
			if url == "(null)" {
				url = ""
			}
		}
		if strings.TrimSpace(l) == "Enabled: Yes" {
			enabled = true
		}
	}
	return url, enabled, nil
}

// legacyURL matches the URL AuthPass 1.1.2 and earlier set: a loopback PAC
// with a nanosecond timestamp as cache buster.
var legacyURL = regexp.MustCompile(`^http://(127\.0\.0\.1|localhost):[0-9]+/[^?#]*\?t=[0-9]{18,}$`)

// owned reports whether the service's current auto-proxy URL is still the one
// AuthPass set. State files written before 1.1.3 do not record it; for those,
// accept only AuthPass's own URL form.
func owned(s state, current string) bool {
	if s.Applied != "" {
		return current == s.Applied
	}
	return legacyURL.MatchString(current)
}

// restore puts back the saved settings of every service whose auto-proxy URL
// is still AuthPass's. A service the user has changed since (or that no longer
// exists) is left alone. The state file is removed once nothing is left to do.
func restore(dir string, run runner) error {
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
	var listed map[string]bool
	// left keeps what still needs restoring after an error.
	var left []state
	for _, s := range states {
		current, _, e := autoproxy(run, s.Service)
		if e != nil {
			if listed == nil {
				list, le := services(run)
				if le != nil {
					errs = append(errs, e.Error())
					left = append(left, s)
					continue
				}
				listed = map[string]bool{}
				for _, svc := range list {
					listed[svc] = true
				}
			}
			if !listed[s.Service] {
				continue // the service is gone
			}
			errs = append(errs, e.Error())
			left = append(left, s)
			continue
		}
		if !owned(s, current) {
			continue // changed by the user; leave it alone
		}
		// Set the enabled state first and the URL last: until the URL changes
		// the service still shows AuthPass's URL, so an interrupted or failed
		// restore is retried later instead of being taken for a user change.
		v := "off"
		if s.Enabled {
			v = "on"
		}
		if _, e = run("-setautoproxystate", s.Service, v); e != nil {
			errs = append(errs, e.Error())
			left = append(left, s)
			continue
		}
		// networksetup rejects an empty URL, so only restore a URL that existed.
		if s.URL != "" {
			if _, e = run("-setautoproxyurl", s.Service, s.URL); e != nil {
				errs = append(errs, e.Error())
				left = append(left, s)
			}
		}
	}
	if len(errs) > 0 {
		if e = writeState(p, left); e != nil {
			errs = append(errs, e.Error())
		}
		return fmt.Errorf("restore: %s", strings.Join(errs, "; "))
	}
	return os.Remove(p)
}

// enable points every network service at url (with a cache-busting query from
// stamp) after saving the previous settings for restore.
func enable(dir, url string, run runner, stamp func() int64) error {
	if e := restore(dir, run); e != nil {
		return e
	}
	list, e := services(run)
	if e != nil {
		return e
	}
	var states []state
	for _, svc := range list {
		current, enabled, e := autoproxy(run, svc)
		if e != nil {
			return e
		}
		states = append(states, state{Service: svc, URL: current, Enabled: enabled, Applied: fmt.Sprintf("%s?t=%d", url, stamp())})
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	if e = writeState(filepath.Join(dir, "proxy-state.json"), states); e != nil {
		return e
	}
	for _, s := range states {
		if _, e = run("-setautoproxyurl", s.Service, s.Applied); e == nil {
			_, e = run("-setautoproxystate", s.Service, "on")
		}
		if e != nil {
			restoreErr := restore(dir, run)
			return fmt.Errorf("enable: %w; restore: %v", e, restoreErr)
		}
	}
	return nil
}

func writeState(p string, states []state) error {
	b, e := json.MarshalIndent(states, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(p+".tmp", b, 0600); e != nil {
		return e
	}
	return os.Rename(p+".tmp", p)
}
