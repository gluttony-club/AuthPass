//go:build darwin

package sysproxy

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestRealService runs enable/restore cycles with the real networksetup, but
// only against a throwaway network service named by AUTHPASS_TEST_SERVICE
// (for example one created with `networksetup -createnetworkservice
// AuthPassTest lo0`). Every command naming another service fails the test
// before it runs. AUTHPASS_TEST_SCENARIO is "nopac" (the service must have no
// PAC URL yet), "leftover" (the service must already have an AuthPass URL,
// as 1.1.3 could leave behind) or "ownpac-off" / "ownpac-on" (a PAC of the
// user's own).
func TestRealService(t *testing.T) {
	name := os.Getenv("AUTHPASS_TEST_SERVICE")
	if name == "" {
		t.Skip("set AUTHPASS_TEST_SERVICE to a throwaway network service")
	}
	run := func(args ...string) (string, error) {
		if args[0] == "-listallnetworkservices" {
			return "An asterisk (*) denotes that a network service is disabled.\n" + name + "\n", nil
		}
		switch args[0] {
		case "-getautoproxyurl", "-setautoproxyurl", "-setautoproxystate":
		default:
			t.Fatalf("refusing to run %v", args)
		}
		if len(args) < 2 || args[1] != name {
			t.Fatalf("refusing to touch another service: %v", args)
		}
		return networksetup(args...)
	}
	get := func() (string, bool) {
		u, on, e := autoproxy(run, name)
		if e != nil {
			if strings.Contains(e.Error(), "parameters were not valid") {
				return "", false
			}
			t.Fatal(e)
		}
		return u, on
	}
	const own = "http://pac.invalid/own.pac"
	scenario := os.Getenv("AUTHPASS_TEST_SCENARIO")
	switch scenario {
	case "nopac":
		if u, _ := get(); u != "" {
			t.Fatalf("service already has a PAC URL %q", u)
		}
	case "leftover":
		if u, _ := get(); !authPassURL.MatchString(u) {
			t.Fatalf("service has no AuthPass URL: %q", u)
		}
	case "ownpac-off", "ownpac-on":
		run("-setautoproxyurl", name, own)
		run("-setautoproxystate", name, map[bool]string{true: "on", false: "off"}[scenario == "ownpac-on"])
	default:
		t.Fatal("unknown AUTHPASS_TEST_SCENARIO", scenario)
	}
	startURL, startOn := get()
	t.Logf("start: URL=%q enabled=%v", startURL, startOn)
	dir := t.TempDir()
	pac := "http://127.0.0.1:18199/proxy.pac"
	for cycle := 1; cycle <= 3; cycle++ {
		if e := enable(dir, pac, run, func() int64 { return time.Now().UnixNano() }); e != nil {
			t.Fatal(cycle, e)
		}
		u, on := get()
		t.Logf("cycle %d enabled:  URL=%q enabled=%v", cycle, u, on)
		if !on || !strings.HasPrefix(u, pac+"?t=") {
			t.Fatal("not enabled")
		}
		if e := restore(dir, run); e != nil {
			t.Fatal(cycle, e)
		}
		u, on = get()
		t.Logf("cycle %d restored: URL=%q enabled=%v", cycle, u, on)
		if startURL == "" || authPassURL.MatchString(startURL) {
			if on || (u != "" && !authPassURL.MatchString(u)) {
				t.Fatal("autoproxy left on or wrong URL")
			}
		} else if u != startURL || on != startOn {
			t.Fatal("not restored to the start state")
		}
	}
}
