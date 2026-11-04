package settings

import (
	"basicauth-helper/internal/config"
	"basicauth-helper/internal/secret"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

//go:embed settings.html
var page []byte

type Manager struct {
	mu                 sync.Mutex
	c                  *config.Config
	path               string
	store              secret.Store
	Token              string
	CAPath             string
	enabled            bool
	Publish            func(*config.Config)
	Changed            func() error
	SetLaunchAtLogin   func(bool) error
	PreferencesChanged func(bool)
	launchError        string
}

func New(c *config.Config, path string, store secret.Store, token string) (*Manager, error) {
	if token == "" {
		token = config.RandomID()
	}
	for i := range c.Rules {
		p, e := store.Get(c.Rules[i].ID)
		if e != nil {
			return nil, e
		}
		c.Rules[i].Password = p
	}
	return &Manager{c: c, path: path, store: store, Token: token}, nil
}

func (m *Manager) LaunchAtLogin() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.c.LaunchAtLogin() }
func (m *Manager) UpdateLaunchAtLogin(v bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.updateLaunchAtLogin(v)
}
func (m *Manager) updateLaunchAtLogin(v bool) error {
	old := m.c.LaunchAtLogin()
	if m.SetLaunchAtLogin != nil {
		if err := m.SetLaunchAtLogin(v); err != nil {
			m.launchError = err.Error()
			return err
		}
	}
	next := *m.c
	next.LaunchAtLoginValue = &v
	if err := config.Save(m.path, &next); err != nil {
		if m.SetLaunchAtLogin != nil {
			_ = m.SetLaunchAtLogin(old)
		}
		m.launchError = err.Error()
		return err
	}
	m.c = &next
	m.launchError = ""
	if m.PreferencesChanged != nil {
		m.PreferencesChanged(v)
	}
	return nil
}
func (m *Manager) SetEnabled(v bool) { m.mu.Lock(); defer m.mu.Unlock(); m.enabled = v }
func (m *Manager) URL() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fmt.Sprintf("http://%s/settings?token=%s", m.c.Listen, m.Token)
}
func (m *Manager) authorize(w http.ResponseWriter, r *http.Request) bool {
	_, port, _ := net.SplitHostPort(m.c.Listen)
	if r.Host != "127.0.0.1:"+port && r.Host != "localhost:"+port {
		http.Error(w, "invalid Host", 403)
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
		http.Error(w, "invalid Origin", 403)
		return false
	}
	token := r.Header.Get("X-Auth-Token")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(m.Token)) != 1 {
		http.Error(w, "unauthorized", 401)
		return false
	}
	return true
}

type inputRule struct {
	config.Rule
	Password      *string `json:"password"`
	ClearPassword bool    `json:"clear_password"`
}

func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.IsAbs() || !m.authorize(w, r) {
		return
	}
	if r.URL.Path == "/settings" && r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/api/status" && r.Method == "GET" {
		json.NewEncoder(w).Encode(map[string]any{"proxy_addr": m.c.Listen, "ca_path": m.CAPath, "system_proxy_enabled": m.enabled})
		return
	}
	if r.URL.Path == "/api/preferences" {
		switch r.Method {
		case "GET":
			json.NewEncoder(w).Encode(map[string]any{"launch_at_login": m.c.LaunchAtLogin(), "launch_at_login_error": m.launchError})
		case "PUT":
			var input struct {
				Launch *bool `json:"launch_at_login"`
			}
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&input); err != nil || input.Launch == nil || dec.Decode(new(any)) != io.EOF {
				http.Error(w, "invalid preferences", 400)
				return
			}
			if err := m.updateLaunchAtLogin(*input.Launch); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.Write([]byte(`{"saved":true}`))
		default:
			w.Header().Set("Allow", "GET, PUT")
			http.Error(w, "method not allowed", 405)
		}
		return
	}
	if r.URL.Path != "/api/rules" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case "GET":
		type view struct {
			config.Rule
			HasPassword bool `json:"has_password"`
		}
		rows := make([]view, 0, len(m.c.Rules))
		for _, v := range m.c.Rules {
			rows = append(rows, view{v, v.Password != ""})
		}
		json.NewEncoder(w).Encode(rows)
	case "PUT":
		var rows []inputRule
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if e := dec.Decode(&rows); e != nil {
			http.Error(w, "invalid rules", 400)
			return
		}
		if dec.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid trailing JSON", 400)
			return
		}
		next := *m.c
		next.Rules = make([]config.Rule, len(rows))
		old := map[string]string{}
		for _, r := range m.c.Rules {
			old[r.ID] = r.Password
		}
		for i, row := range rows {
			v := row.Rule
			v.Password = old[v.ID]
			if row.ClearPassword {
				if row.Password != nil && *row.Password != "" {
					http.Error(w, "clear conflicts with password", 400)
					return
				}
				v.Password = ""
			} else if row.Password != nil && *row.Password != "" {
				v.Password = *row.Password
			}
			next.Rules[i] = v
		}
		if e := config.Validate(next.Rules); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		// Roll back completed secret operations if persistence fails. Publish only after all writes succeed.
		restore := func() {
			for id, p := range old {
				_ = m.store.Set(id, p)
			}
			for _, r := range next.Rules {
				if _, ok := old[r.ID]; !ok {
					_ = m.store.Delete(r.ID)
				}
			}
		}
		for _, r := range next.Rules {
			if e := m.store.Set(r.ID, r.Password); e != nil {
				restore()
				http.Error(w, "secret save failed", 500)
				return
			}
		}
		keep := map[string]bool{}
		for _, r := range next.Rules {
			keep[r.ID] = true
		}
		for id := range old {
			if !keep[id] {
				if e := m.store.Delete(id); e != nil {
					restore()
					http.Error(w, "secret delete failed", 500)
					return
				}
			}
		}
		if e := config.Save(m.path, &next); e != nil {
			restore()
			http.Error(w, "config save failed", 500)
			return
		}
		m.c = &next
		if m.Publish != nil {
			m.Publish(&next)
		}
		if m.Changed != nil {
			if e := m.Changed(); e != nil {
				http.Error(w, "saved; PAC refresh failed", 500)
				return
			}
		}
		w.Write([]byte(`{"saved":true}`))
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", 405)
	}
}
