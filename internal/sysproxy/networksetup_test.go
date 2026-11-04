package sysproxy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type svc struct {
	url   string
	on    bool
	fresh bool // never had proxy settings: -getautoproxyurl fails
}

// fake simulates networksetup for a set of services, including behaviour seen
// on a real Mac: -setautoproxyurl also turns autoproxy on, an empty URL is
// rejected, and a service that never had proxy settings cannot be queried.
type fake struct {
	svcs  map[string]*svc
	order []string
	calls []string
	fail  string // fail any command that mentions this
}

func newFake(names ...string) *fake {
	f := &fake{svcs: map[string]*svc{}}
	for _, n := range names {
		f.svcs[n] = &svc{}
		f.order = append(f.order, n)
	}
	return f
}

func (f *fake) run(args ...string) (string, error) {
	call := strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.fail != "" && strings.Contains(call, f.fail) {
		return "", errors.New("networksetup failed: " + call)
	}
	switch args[0] {
	case "-listallnetworkservices":
		out := "An asterisk (*) denotes that a network service is disabled.\n"
		for _, n := range f.order {
			if f.svcs[n] != nil {
				out += n + "\n"
			}
		}
		return out, nil
	}
	s := f.svcs[args[1]]
	if s == nil {
		return "", errors.New("** Error: The parameters were not valid.")
	}
	switch args[0] {
	case "-getautoproxyurl":
		if s.fresh {
			return "", errors.New("networksetup [-getautoproxyurl]: exit status 4: ** Error: The parameters were not valid.")
		}
		u, on := s.url, "No"
		if u == "" {
			u = "(null)"
		}
		if s.on {
			on = "Yes"
		}
		return fmt.Sprintf("URL: %s\nEnabled: %s\n", u, on), nil
	case "-setautoproxyurl":
		if args[2] == "" {
			return "", errors.New("** Error: The parameters were not valid.")
		}
		s.url, s.on, s.fresh = args[2], true, false
	case "-setautoproxystate":
		s.on, s.fresh = args[2] == "on", false
	}
	return "", nil
}

func (f *fake) sets() int {
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, "-set") {
			n++
		}
	}
	return n
}

const pac = "http://127.0.0.1:18080/proxy.pac"

func stamp() int64 { return 42 }

func TestEnableRestore(t *testing.T) {
	dir := t.TempDir()
	f := newFake("Wi-Fi", "Ethernet")
	f.svcs["Wi-Fi"].url, f.svcs["Wi-Fi"].on = "http://corp.example/proxy.pac", true
	if e := enable(dir, pac, f.run, stamp); e != nil {
		t.Fatal(e)
	}
	for _, n := range f.order {
		if s := f.svcs[n]; s.url != pac+"?t=42" || !s.on {
			t.Fatal(n, *s)
		}
	}
	if e := restore(dir, f.run); e != nil {
		t.Fatal(e)
	}
	if s := f.svcs["Wi-Fi"]; s.url != "http://corp.example/proxy.pac" || !s.on {
		t.Fatal(*s)
	}
	if f.svcs["Ethernet"].on {
		t.Fatal("ethernet must be off again")
	}
	if _, e := os.Stat(filepath.Join(dir, "proxy-state.json")); !os.IsNotExist(e) {
		t.Fatal("state not removed", e)
	}
}

// After a crash the user changed one service by hand: Restore must leave it
// alone, still restore the others, and drop the stale state.
func TestRestoreSkipsServicesChangedByUser(t *testing.T) {
	dir := t.TempDir()
	f := newFake("Wi-Fi", "Ethernet")
	f.svcs["Wi-Fi"].url, f.svcs["Wi-Fi"].on = "http://corp.example/proxy.pac", true
	f.svcs["Ethernet"].url, f.svcs["Ethernet"].on = "http://old.example/a.pac", false
	if e := enable(dir, pac, f.run, stamp); e != nil {
		t.Fatal(e)
	}
	f.svcs["Wi-Fi"].url, f.svcs["Wi-Fi"].on = "http://mine.example/new.pac", true // user's change
	f.calls = nil
	if e := restore(dir, f.run); e != nil {
		t.Fatal(e)
	}
	if s := f.svcs["Wi-Fi"]; s.url != "http://mine.example/new.pac" || !s.on {
		t.Fatal("user's setting overwritten:", *s)
	}
	if s := f.svcs["Ethernet"]; s.url != "http://old.example/a.pac" || s.on {
		t.Fatal(*s)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "-set") && strings.Contains(c, "Wi-Fi") {
			t.Fatal("touched Wi-Fi:", c)
		}
	}
	if _, e := os.Stat(filepath.Join(dir, "proxy-state.json")); !os.IsNotExist(e) {
		t.Fatal("stale state kept", e)
	}
	// Different AuthPass URL (other port or stamp) is not ours either.
	f2 := newFake("Wi-Fi")
	if e := enable(dir, pac, f2.run, stamp); e != nil {
		t.Fatal(e)
	}
	f2.svcs["Wi-Fi"].url = pac + "?t=43"
	f2.calls = nil
	if e := restore(dir, f2.run); e != nil || f2.sets() != 0 {
		t.Fatal(e, f2.calls)
	}
}

func TestRestoreRemovedServiceAndErrors(t *testing.T) {
	dir := t.TempDir()
	f := newFake("Wi-Fi", "USB")
	if e := enable(dir, pac, f.run, stamp); e != nil {
		t.Fatal(e)
	}
	f.svcs["USB"] = nil // adapter unplugged
	f.fail = "-setautoproxystate Wi-Fi"
	if e := restore(dir, f.run); e == nil {
		t.Fatal("expected error")
	}
	if _, e := os.Stat(filepath.Join(dir, "proxy-state.json")); e != nil {
		t.Fatal("state must be kept for a retry after an error", e)
	}
	f.fail = ""
	if e := restore(dir, f.run); e != nil {
		t.Fatal("a removed service must not block restore:", e)
	}
	if f.svcs["Wi-Fi"].on {
		t.Fatal("not restored")
	}
	// A query failure for a service that still exists keeps the state.
	if e := enable(dir, pac, f.run, stamp); e != nil {
		t.Fatal(e)
	}
	f.fail = "-getautoproxyurl Wi-Fi"
	if e := restore(dir, f.run); e == nil {
		t.Fatal("expected error")
	}
	if _, e := os.Stat(filepath.Join(dir, "proxy-state.json")); e != nil {
		t.Fatal("state must be kept", e)
	}
}

// State files from 1.1.2 and earlier have no Applied URL.
func TestRestoreLegacyState(t *testing.T) {
	dir := t.TempDir()
	f := newFake("Wi-Fi", "Ethernet")
	f.svcs["Wi-Fi"].url, f.svcs["Wi-Fi"].on = pac+"?t=1793763171929078000", true
	f.svcs["Ethernet"].url, f.svcs["Ethernet"].on = "http://mine.example/x.pac", true
	legacy := `[{"Service":"Wi-Fi","URL":"http://corp.example/proxy.pac","Enabled":false},{"Service":"Ethernet","URL":"","Enabled":false}]`
	if e := os.WriteFile(filepath.Join(dir, "proxy-state.json"), []byte(legacy), 0600); e != nil {
		t.Fatal(e)
	}
	if e := restore(dir, f.run); e != nil {
		t.Fatal(e)
	}
	if s := f.svcs["Wi-Fi"]; s.url != "http://corp.example/proxy.pac" || s.on {
		t.Fatal(*s)
	}
	if s := f.svcs["Ethernet"]; s.url != "http://mine.example/x.pac" || !s.on {
		t.Fatal("user's setting overwritten:", *s)
	}
}

func TestEnableFailureRestoresOnlyChangedServices(t *testing.T) {
	dir := t.TempDir()
	f := newFake("A", "B")
	f.svcs["A"].url, f.svcs["A"].on = "http://a.example/p.pac", true
	f.svcs["B"].url = "http://b.example/p.pac"
	f.fail = "-setautoproxyurl B"
	if e := enable(dir, pac, f.run, stamp); e == nil || !strings.Contains(e.Error(), "restore: <nil>") {
		t.Fatal(e)
	}
	if s := f.svcs["A"]; s.url != "http://a.example/p.pac" || !s.on {
		t.Fatal(*s)
	}
	if s := f.svcs["B"]; s.url != "http://b.example/p.pac" || s.on {
		t.Fatal(*s)
	}
}

// A restore that fails (or is interrupted) part way must still finish on
// retry: either step failing, and a crash right after the URL was set (which
// turned autoproxy on).
func TestRestoreRetryAfterPartialFailure(t *testing.T) {
	for _, step := range []string{"-setautoproxystate", "-setautoproxyurl", "crash"} {
		dir := t.TempDir()
		f := newFake("Wi-Fi")
		f.svcs["Wi-Fi"].url, f.svcs["Wi-Fi"].on = "http://corp.example/proxy.pac", false
		if e := enable(dir, pac, f.run, stamp); e != nil {
			t.Fatal(e)
		}
		if step == "crash" {
			// AuthPass dies right after setting the URL, which turned
			// autoproxy on.
			crash := func(args ...string) (string, error) {
				out, e := f.run(args...)
				if args[0] == "-setautoproxyurl" {
					panic("crash")
				}
				return out, e
			}
			func() {
				defer func() { recover() }()
				restore(dir, crash)
			}()
			if s := f.svcs["Wi-Fi"]; !s.on {
				t.Fatal("crash simulation did not turn autoproxy on")
			}
		} else {
			f.fail = step
			if e := restore(dir, f.run); e == nil {
				t.Fatal("expected error")
			}
		}
		f.fail = ""
		if e := restore(dir, f.run); e != nil {
			t.Fatal(e)
		}
		if s := f.svcs["Wi-Fi"]; s.url != "http://corp.example/proxy.pac" || s.on {
			t.Fatal(step, "not restored on retry:", *s)
		}
		if _, e := os.Stat(filepath.Join(dir, "proxy-state.json")); !os.IsNotExist(e) {
			t.Fatal("state not removed", e)
		}
	}
}

// A user who sets their original URL back by hand while AuthPass runs keeps it.
func TestRestoreKeepsOriginalURLSetByUser(t *testing.T) {
	dir := t.TempDir()
	f := newFake("Wi-Fi")
	f.svcs["Wi-Fi"].url = "http://corp.example/proxy.pac"
	if e := enable(dir, pac, f.run, stamp); e != nil {
		t.Fatal(e)
	}
	f.run("-setautoproxyurl", "Wi-Fi", "http://corp.example/proxy.pac")
	if e := restore(dir, f.run); e != nil {
		t.Fatal(e)
	}
	if s := f.svcs["Wi-Fi"]; !s.on {
		t.Fatal("user's change was overwritten")
	}
}

// A never-configured service that AuthPass did not get to change (enable
// failed or crashed first) must not block restore.
func TestRestoreUntouchedFreshService(t *testing.T) {
	dir := t.TempDir()
	f := newFake("Wi-Fi", "Dock")
	f.svcs["Dock"].fresh = true
	f.fail = "-setautoproxyurl Wi-Fi"
	if e := enable(dir, pac, f.run, stamp); e == nil {
		t.Fatal("expected error")
	}
	if e := writeState(filepath.Join(dir, "proxy-state.json"), []state{{Service: "Dock"}}); e != nil {
		t.Fatal(e)
	}
	f.fail = ""
	if e := restore(dir, f.run); e != nil {
		t.Fatal(e)
	}
	if !f.svcs["Dock"].fresh {
		t.Fatal("untouched service was changed")
	}
	if _, e := os.Stat(filepath.Join(dir, "proxy-state.json")); !os.IsNotExist(e) {
		t.Fatal("state not removed", e)
	}
}

// Repeated enable/quit cycles must always end in the original state. A user
// without a PAC keeps AuthPass's URL afterwards (networksetup cannot clear a
// URL) but autoproxy must be off.
func TestEnableRestoreCycles(t *testing.T) {
	for _, v := range []struct {
		name  string
		start svc
	}{
		{"no PAC", svc{}},
		{"never configured", svc{fresh: true}},
		{"own PAC disabled", svc{url: "http://corp.example/proxy.pac"}},
		{"own PAC enabled", svc{url: "http://corp.example/proxy.pac", on: true}},
		{"left over by 1.1.3, off", svc{url: pac + "?t=1793763171929078000"}},
		{"left over by 1.1.3, on", svc{url: pac + "?t=1793763171929078000", on: true}},
	} {
		t.Run(v.name, func(t *testing.T) {
			dir := t.TempDir()
			f := newFake("Wi-Fi")
			*f.svcs["Wi-Fi"] = v.start
			for cycle := 1; cycle <= 3; cycle++ {
				if e := enable(dir, pac, f.run, func() int64 { return int64(1793763171929078000 + cycle) }); e != nil {
					t.Fatal(cycle, e)
				}
				if s := f.svcs["Wi-Fi"]; !s.on || !strings.HasPrefix(s.url, pac+"?t=") {
					t.Fatal(cycle, "not enabled:", *s)
				}
				if e := restore(dir, f.run); e != nil {
					t.Fatal(cycle, e)
				}
				s := *f.svcs["Wi-Fi"]
				want := v.start.url
				if want == "" || authPassURL.MatchString(want) {
					// No PAC of the user's own: off; the URL can't be cleared.
					if s.on || (s.url != "" && !authPassURL.MatchString(s.url)) {
						t.Fatal(cycle, "autoproxy left on or wrong URL:", s)
					}
					continue
				}
				if s.url != want || s.on != v.start.on {
					t.Fatalf("cycle %d: got %+v, want %+v", cycle, s, v.start)
				}
			}
		})
	}
}

func TestOwnedLegacy(t *testing.T) {
	for url, want := range map[string]bool{
		pac + "?t=1793763171929078000":                           true,
		"http://localhost:18080/proxy.pac?t=1793763171929078000": true,
		"http://127.0.0.1:7890/other.pac?t=custom":               false,
		"http://127.0.0.1:7890/clash.pac":                        false,
		"http://127.0.0.1:7890/x.pac?t=12":                       false,
		"http://corp.example/proxy.pac?t=1793763171929078000":    false,
		"": false,
	} {
		if owned(state{}, url) != want {
			t.Error(url, !want)
		}
	}
}

// If even listing services fails, the service must stay in the state file.
func TestRestoreKeepsStateWhenListingFails(t *testing.T) {
	dir := t.TempDir()
	f := newFake("Wi-Fi", "Ethernet")
	if e := enable(dir, pac, f.run, stamp); e != nil {
		t.Fatal(e)
	}
	f.fail = "-getautoproxyurl Wi-Fi"
	f.svcs["Wi-Fi"].url = pac + "?t=42"
	failList := &fake{svcs: f.svcs, order: f.order}
	run := func(args ...string) (string, error) {
		if args[0] == "-listallnetworkservices" || (args[0] == "-getautoproxyurl" && args[1] == "Wi-Fi") {
			return "", errors.New("networksetup failed")
		}
		return failList.run(args...)
	}
	if e := restore(dir, run); e == nil {
		t.Fatal("expected error")
	}
	if e := restore(dir, f.run); e == nil {
		t.Fatal("Wi-Fi must still be pending")
	}
	f.fail = ""
	if e := restore(dir, f.run); e != nil {
		t.Fatal(e)
	}
	if f.svcs["Wi-Fi"].on || f.svcs["Ethernet"].on {
		t.Fatal("not restored", *f.svcs["Wi-Fi"], *f.svcs["Ethernet"])
	}
}
