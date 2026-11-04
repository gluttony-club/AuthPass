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
// changed it, plus the URL AuthPass set (Applied). Restoring is saved before
// restore sets the original URL back, so a restore that stops between the URL
// and the enabled state can be finished later.
type state struct {
	Service   string
	URL       string
	Enabled   bool
	Applied   string `json:",omitempty"`
	Restoring bool   `json:",omitempty"`
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

// authPassURL matches the URLs AuthPass sets: a loopback PAC with a
// nanosecond timestamp as cache buster. Recognition is by this pattern only.
var authPassURL = regexp.MustCompile(`^http://(127\.0\.0\.1|localhost):[0-9]+/[^?#]*\?t=[0-9]{18,}$`)

// original normalises a saved setting. networksetup cannot clear a URL, so
// after restoring a service that had none, AuthPass's URL stays behind (turned
// off). Such a URL is never the user's own: it is treated as "no PAC, off",
// so it is never restored, and restoring it would also turn autoproxy on.
// A service without a URL is always restored as off.
func original(s state) state {
	if s.URL == "" || authPassURL.MatchString(s.URL) {
		s.URL, s.Enabled = "", false
	}
	return s
}

// owned reports whether restore may change the service: its current URL is
// still the one AuthPass set (for state files before 1.1.3, which do not
// record it, any URL of AuthPass's form), or it is already the original URL
// because an earlier restore set the URL and then failed or was interrupted
// before setting the enabled state. Without Restoring, a service that shows
// its original URL again was changed back by the user and is left alone.
func owned(s state, current string) bool {
	if s.Restoring && s.URL != "" && current == s.URL {
		return true
	}
	if s.Applied != "" {
		return current == s.Applied
	}
	return authPassURL.MatchString(current)
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
	for i, s := range states {
		s = original(s)
		current, _, e := autoproxy(run, s.Service)
		if e != nil {
			// A service that never had proxy settings cannot be queried;
			// AuthPass did not get to change it, so there is nothing to undo.
			untouched := strings.Contains(e.Error(), "parameters were not valid")
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
			if !listed[s.Service] || untouched {
				continue // the service is gone or was never changed
			}
			errs = append(errs, e.Error())
			left = append(left, s)
			continue
		}
		if !owned(s, current) {
			continue // changed by the user; leave it alone
		}
		// Set the URL first: -setautoproxyurl also turns autoproxy on, so the
		// enabled state must come last. networksetup rejects an empty URL, so
		// only a URL that existed is restored. Restoring is saved first so
		// that, if the state step fails or never runs, a later restore still
		// owns the service.
		if s.URL != "" && current != s.URL {
			if !s.Restoring {
				s.Restoring, states[i].Restoring = true, true
				// Best effort: restoring matters more. If this write fails, only
				// a crash before the state step below loses the progress.
				_ = writeState(p, states)
			}
			if _, e = run("-setautoproxyurl", s.Service, s.URL); e != nil {
				// The URL did not change, so a later restore does not need
				// Restoring and must not take a user's change for progress.
				s.Restoring = false
				errs = append(errs, e.Error())
				left = append(left, s)
				continue
			}
		}
		v := "off"
		if s.Enabled {
			v = "on"
		}
		if _, e = run("-setautoproxystate", s.Service, v); e != nil {
			errs = append(errs, e.Error())
			left = append(left, s)
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
			// A listed service that has never had proxy settings makes
			// networksetup report invalid parameters: it has no PAC.
			if !strings.Contains(e.Error(), "parameters were not valid") {
				return e
			}
			current, enabled = "", false
		}
		states = append(states, original(state{Service: svc, URL: current, Enabled: enabled, Applied: fmt.Sprintf("%s?t=%d", url, stamp())}))
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
