package settings

import (
	"errors"
	"fmt"
	"github.com/gluttony-club/AuthPass/internal/config"
	"github.com/gluttony-club/AuthPass/internal/secret"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestAPI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	c, e := config.Load(path)
	if e != nil {
		t.Fatal(e)
	}
	m, e := New(c, path, secret.NewFile(dir), "test-token")
	if e != nil {
		t.Fatal(e)
	}
	call := func(method, body, token, host, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/rules", strings.NewReader(body))
		r.Host = host
		r.Header.Set("X-Auth-Token", token)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		return w
	}
	for _, v := range []struct {
		token, host, origin string
		code                int
	}{{"", "127.0.0.1:18080", "", 401}, {"test-token", "evil.test:18080", "", 403}, {"test-token", "127.0.0.1:18080", "http://evil.test", 403}, {"test-token", "localhost:18080", "http://localhost:18080", 200}} {
		if w := call("GET", "", v.token, v.host, v.origin); w.Code != v.code {
			t.Fatal(w.Code, w.Body)
		}
	}
	put := func(body string) {
		t.Helper()
		w := call("PUT", body, "test-token", "127.0.0.1:18080", "")
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}
	put(`[{"id":"dev","name":"测试","host_prefix":"dev.","username":"user","password":"private-secret","enabled":true,"allow_http":true}]`)
	w := call("GET", "", "test-token", "127.0.0.1:18080", "")
	if strings.Contains(w.Body.String(), "private-secret") || !strings.Contains(w.Body.String(), `"has_password":true`) || !strings.Contains(w.Body.String(), `"allow_http":true`) {
		t.Fatal(w.Body)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "private-secret") || strings.Contains(string(b), "password") {
		t.Fatal(string(b))
	}
	for _, password := range []string{"", `,"password":null`, `,"password":""`} {
		put(`[{"id":"dev","host_prefix":"dev.","username":"user","enabled":true` + password + `}]`)
		s, _ := secret.NewFile(dir).Get("dev")
		if s != "private-secret" {
			t.Fatal("lost password")
		}
	}
	loaded, _ := config.Load(path)
	again, e := New(loaded, path, secret.NewFile(dir), "")
	if e != nil || again.c.Rules[0].Password != "private-secret" {
		t.Fatal(e)
	}
	if st, e := os.Stat(filepath.Join(dir, "secrets.json")); e == nil && st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); call(http.MethodGet, "", "test-token", "127.0.0.1:18080", "") }()
	}
	wg.Wait()
	put(`[{"id":"dev","host_prefix":"dev.","username":"user","clear_password":true,"password":"","enabled":true}]`)
	p, _ := secret.NewFile(dir).Get("dev")
	if p != "" {
		t.Fatal("not cleared")
	}
	put(`[]`)
}

func TestPreferences(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(c, path, secret.NewFile(dir), "token")
	if err != nil {
		t.Fatal(err)
	}
	state := true
	m.SetLaunchAtLogin = func(v bool) error { state = v; return nil }
	call := func(method, body, token, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/preferences", strings.NewReader(body))
		r.Host = "localhost:18080"
		r.Header.Set("X-Auth-Token", token)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "", "token", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"launch_at_login":true`) {
		t.Fatal(w)
	}
	for _, method := range []string{"GET", "PUT"} {
		if w := call(method, `{"launch_at_login":false}`, "", ""); w.Code != 401 {
			t.Fatal(w)
		}
		if w := call(method, `{"launch_at_login":false}`, "token", "http://evil.test"); w.Code != 403 {
			t.Fatal(w)
		}
	}
	for _, body := range []string{`{}`, `{"launch_at_login":null}`, `{"launch_at_login":true} {}`} {
		if w := call("PUT", body, "token", ""); w.Code != 400 {
			t.Fatal(w)
		}
	}
	if w := call("PUT", `{"launch_at_login":false}`, "token", ""); w.Code != 200 || state {
		t.Fatal(w, state)
	}
	loaded, err := config.Load(path)
	if err != nil || loaded.LaunchAtLogin() || len(loaded.Rules) != len(c.Rules) {
		t.Fatal(loaded, err)
	}
	m.SetLaunchAtLogin = func(bool) error {
		return fmt.Errorf("请先把应用拖到「应用程序」文件夹再开启开机自启")
	}
	if w := call("PUT", `{"launch_at_login":true}`, "token", ""); w.Code != 500 {
		t.Fatal(w)
	}
	if w := call("GET", "", "token", ""); !strings.Contains(w.Body.String(), `"launch_at_login":false`) || !strings.Contains(w.Body.String(), "应用程序") {
		t.Fatal(w)
	}
}

func TestDomains(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(c, path, secret.NewFile(dir), "token")
	if err != nil {
		t.Fatal(err)
	}
	var published *config.Config
	changed := 0
	m.Publish = func(c *config.Config) { published = c }
	m.Changed = func() error { changed++; return nil }
	call := func(method, body, token, host, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/domains", strings.NewReader(body))
		r.Host = host
		r.Header.Set("X-Auth-Token", token)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		return w
	}
	for _, method := range []string{"GET", "PUT"} {
		for _, v := range []struct {
			token, host, origin string
			code                int
		}{{"", "localhost:18080", "", 401}, {"token", "evil.test:18080", "", 403}, {"token", "localhost:18080", "http://evil.test", 403}} {
			if w := call(method, `{"trusted_domains":["example.com"]}`, v.token, v.host, v.origin); w.Code != v.code {
				t.Fatal(w)
			}
		}
	}
	if w := call("GET", "", "token", "localhost:18080", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"trusted_domains":[]`) {
		t.Fatal(w)
	}
	for _, body := range []string{`{}`, `{"trusted_domains":null}`, `{"trusted_domains":["*.example.com"]}`, `{"trusted_domains":["localhost"]}`, `{"trusted_domains":[]} {}`} {
		if w := call("PUT", body, "token", "localhost:18080", ""); w.Code != 400 {
			t.Fatal(w)
		}
	}
	if w := call("PUT", `{"trusted_domains":[" EXAMPLE.COM ","example.com","example.net"]}`, "token", "localhost:18080", ""); w.Code != 200 {
		t.Fatal(w)
	}
	if published == nil || strings.Join(published.TrustedDomains, ",") != "example.com,example.net" || changed != 1 {
		t.Fatal(published, changed)
	}
	loaded, err := config.Load(path)
	if err != nil || strings.Join(loaded.TrustedDomains, ",") != "example.com,example.net" {
		t.Fatal(loaded, err)
	}
	if w := call("GET", "", "token", "localhost:18080", ""); !strings.Contains(w.Body.String(), `"trusted_domains":["example.com","example.net"]`) {
		t.Fatal(w)
	}
	if w := call("PUT", `{"trusted_domains":[]}`, "token", "localhost:18080", ""); w.Code != 200 || len(m.c.TrustedDomains) != 0 {
		t.Fatal(w)
	}
}

// flakyStore wraps the file store and fails selected operations.
type flakyStore struct {
	secret.Store
	getErr      map[string]error
	setErr      map[string]error
	setCalls    []string
	rollbackErr error
}

func (s *flakyStore) Get(id string) (string, error) {
	if e := s.getErr[id]; e != nil {
		return "", e
	}
	return s.Store.Get(id)
}
func (s *flakyStore) Set(id, p string) error {
	s.setCalls = append(s.setCalls, id)
	if e := s.setErr[id]; e != nil {
		return e
	}
	if s.rollbackErr != nil && len(s.setCalls) > 1 {
		return s.rollbackErr
	}
	return s.Store.Set(id, p)
}

func TestUnreadablePasswordKeepsRunning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	files := secret.NewFile(dir)
	if e := files.Set("a", "secret-a"); e != nil {
		t.Fatal(e)
	}
	if e := files.Set("b", "secret-b"); e != nil {
		t.Fatal(e)
	}
	c := &config.Config{Listen: "127.0.0.1:18080", PACPath: "/proxy.pac", TrustedDomains: []string{"example.com"}, Rules: []config.Rule{
		{ID: "a", Name: "A", HostPrefix: "a.", Username: "u", Enabled: true},
		{ID: "b", Name: "B", HostPrefix: "b.", Username: "u", Enabled: true},
	}}
	store := &flakyStore{Store: files, getErr: map[string]error{"b": errors.New("keychain operation failed: user denied")}}
	m, e := New(c, path, store, "test-token")
	if e != nil {
		t.Fatal("New must not fail on unreadable passwords:", e)
	}
	if c.Rules[0].Password != "secret-a" || c.Rules[1].Password != "" {
		t.Fatal(c.Rules)
	}
	if st := m.SecretStatus(); !strings.Contains(st, "1 条") || !strings.Contains(st, "B") || !strings.Contains(st, "user denied") {
		t.Fatal(st)
	}
	call := func(method, target, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r.Host = "127.0.0.1:18080"
		r.Header.Set("X-Auth-Token", "test-token")
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		return w
	}
	w := call("GET", "/api/rules", "")
	if !strings.Contains(w.Body.String(), `"password_error":"keychain operation failed: user denied"`) || strings.Count(w.Body.String(), "password_error") != 1 {
		t.Fatal(w.Body)
	}
	if w := call("GET", "/api/status", ""); !strings.Contains(w.Body.String(), "user denied") {
		t.Fatal(w.Body)
	}
	var status string
	m.SecretsChanged = func(s string) { status = s }
	// Saving without touching rule b must not overwrite its stored password.
	if w := call("PUT", "/api/rules", `[{"id":"a","name":"A","host_prefix":"a.","username":"u","enabled":true},{"id":"b","name":"B","host_prefix":"b.","username":"u","enabled":true}]`); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if p, _ := files.Get("b"); p != "secret-b" {
		t.Fatalf("unreadable password overwritten: %q", p)
	}
	for _, id := range store.setCalls {
		if id == "b" {
			t.Fatal("Set called for unreadable rule")
		}
	}
	if status == "" {
		t.Fatal("status cleared while b still unreadable")
	}
	// Entering a new password resolves the error.
	if w := call("PUT", "/api/rules", `[{"id":"a","name":"A","host_prefix":"a.","username":"u","enabled":true},{"id":"b","name":"B","host_prefix":"b.","username":"u","password":"new-b","enabled":true}]`); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if p, _ := files.Get("b"); p != "new-b" || status != "" || m.SecretStatus() != "" {
		t.Fatalf("p=%q status=%q", p, status)
	}
}

func TestRollbackErrorsAreReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	files := secret.NewFile(dir)
	_ = files.Set("a", "secret-a")
	c := &config.Config{Listen: "127.0.0.1:18080", PACPath: "/proxy.pac", Rules: []config.Rule{{ID: "a", HostPrefix: "a.", Username: "u", Enabled: true}}}
	store := &flakyStore{Store: files, setErr: map[string]error{"z": errors.New("user canceled")}, rollbackErr: errors.New("rollback boom")}
	m, e := New(c, path, store, "test-token")
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("PUT", "/api/rules", strings.NewReader(`[{"id":"a","host_prefix":"a.","username":"u","password":"new-a","enabled":true},{"id":"z","host_prefix":"z.","username":"u","password":"p","enabled":true}]`))
	r.Host = "127.0.0.1:18080"
	r.Header.Set("X-Auth-Token", "test-token")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)
	if w.Code != 500 || !strings.Contains(w.Body.String(), "user canceled") || !strings.Contains(w.Body.String(), "rollback failed") || !strings.Contains(w.Body.String(), "rollback boom") {
		t.Fatal(w.Code, w.Body)
	}
}

func TestLaunchAtLoginRollbackError(t *testing.T) {
	dir := t.TempDir()
	// A directory where the config file should be makes Save fail.
	path := filepath.Join(dir, "config.json")
	if e := os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	c := &config.Config{Listen: "127.0.0.1:18080", PACPath: "/proxy.pac"}
	m, e := New(c, path, secret.NewFile(dir), "test-token")
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	m.SetLaunchAtLogin = func(bool) error {
		calls++
		if calls > 1 {
			return errors.New("launchd boom")
		}
		return nil
	}
	err := m.UpdateLaunchAtLogin(false)
	if err == nil || !strings.Contains(err.Error(), "rollback") || !strings.Contains(err.Error(), "launchd boom") {
		t.Fatal(err)
	}
}

// TestUnreadablePasswordSurvivesFailedSave checks that the keychain item of a
// rule whose password could not be read is never changed before the config is
// saved, because a rollback could not restore it.
func TestUnreadablePasswordSurvivesFailedSave(t *testing.T) {
	const a = `{"id":"a","name":"A","host_prefix":"a.","username":"u","enabled":true}`
	for _, v := range []struct {
		name, body string
	}{
		{"delete", `[` + a + `]`},
		{"set", `[` + a + `,{"id":"b","name":"B","host_prefix":"b.","username":"u","password":"new-b","enabled":true}]`},
		{"clear", `[` + a + `,{"id":"b","name":"B","host_prefix":"b.","username":"u","clear_password":true,"enabled":true}]`},
	} {
		t.Run(v.name, func(t *testing.T) {
			dir := t.TempDir()
			files := secret.NewFile(dir)
			_ = files.Set("a", "secret-a")
			_ = files.Set("b", "secret-b")
			c := &config.Config{Listen: "127.0.0.1:18080", PACPath: "/proxy.pac", TrustedDomains: []string{"example.com"}, Rules: []config.Rule{
				{ID: "a", Name: "A", HostPrefix: "a.", Username: "u", Enabled: true},
				{ID: "b", Name: "B", HostPrefix: "b.", Username: "u", Enabled: true},
			}}
			store := &flakyStore{Store: files, getErr: map[string]error{"b": errors.New("denied")}}
			m, _ := New(c, filepath.Join(dir, "config.json"), store, "test-token")
			if c.Target("b.example.com") != nil {
				t.Fatal("degraded rule must not inject credentials")
			}
			m.save = func(string, *config.Config) error { return errors.New("disk full") }
			r := httptest.NewRequest("PUT", "/api/rules", strings.NewReader(v.body))
			r.Host = "127.0.0.1:18080"
			r.Header.Set("X-Auth-Token", "test-token")
			w := httptest.NewRecorder()
			m.ServeHTTP(w, r)
			if w.Code != 500 || !strings.Contains(w.Body.String(), "disk full") || strings.Contains(w.Body.String(), "rollback failed") {
				t.Fatal(w.Code, w.Body)
			}
			if p, err := files.Get("b"); err != nil || p != "secret-b" {
				t.Fatalf("unreadable password changed before save: %q %v", p, err)
			}
			if p, _ := files.Get("a"); p != "secret-a" {
				t.Fatalf("readable password not rolled back: %q", p)
			}
			if len(m.c.Rules) != 2 || m.SecretStatus() == "" {
				t.Fatal("state changed after failed save")
			}
			// Once saving works, the change is applied.
			m.save = config.Save
			w = httptest.NewRecorder()
			r = httptest.NewRequest("PUT", "/api/rules", strings.NewReader(v.body))
			r.Host = "127.0.0.1:18080"
			r.Header.Set("X-Auth-Token", "test-token")
			m.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			p, _ := files.Get("b")
			want := map[string]string{"delete": "", "set": "new-b", "clear": ""}[v.name]
			if p != want || m.SecretStatus() != "" {
				t.Fatalf("after save: %q status %q", p, m.SecretStatus())
			}
		})
	}
}

// TestUnreadablePasswordDeferredWriteFails covers a keychain failure after the
// config was saved: the original item stays and the error says so.
func TestUnreadablePasswordDeferredWriteFails(t *testing.T) {
	dir := t.TempDir()
	files := secret.NewFile(dir)
	_ = files.Set("b", "secret-b")
	c := &config.Config{Listen: "127.0.0.1:18080", PACPath: "/proxy.pac", TrustedDomains: []string{"example.com"}, Rules: []config.Rule{{ID: "b", Name: "B", HostPrefix: "b.", Username: "u", Enabled: true}}}
	store := &flakyStore{Store: files, getErr: map[string]error{"b": errors.New("denied")}, setErr: map[string]error{"b": errors.New("user canceled")}}
	m, _ := New(c, filepath.Join(dir, "config.json"), store, "test-token")
	r := httptest.NewRequest("PUT", "/api/rules", strings.NewReader(`[{"id":"b","name":"B","host_prefix":"b.","username":"u","password":"new-b","enabled":true}]`))
	r.Host = "127.0.0.1:18080"
	r.Header.Set("X-Auth-Token", "test-token")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)
	if w.Code != 500 || !strings.Contains(w.Body.String(), "left unchanged") || !strings.Contains(w.Body.String(), "user canceled") {
		t.Fatal(w.Code, w.Body)
	}
	if p, _ := files.Get("b"); p != "secret-b" {
		t.Fatal("original item changed", p)
	}
	if m.c.Rules[0].Password != "" || m.c.Target("b.example.com") != nil || m.SecretStatus() == "" {
		t.Fatal("rule must stay degraded")
	}
}
