package settings

import (
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
