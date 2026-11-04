package settings

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gluttony-club/AuthPass/internal/config"
	"github.com/gluttony-club/AuthPass/internal/secret"
	"io"
	"net"
	"net/http"
	"sort"
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
	// SecretsChanged is called with the new SecretStatus after rules are saved.
	SecretsChanged func(string)
	launchError    string
	// secretErrors holds rule IDs whose stored password could not be read
	// (for example the user denied keychain access). Those rules run without a
	// password, and their stored item is left untouched until the user sets or
	// clears the password.
	secretErrors map[string]string
}

func New(c *config.Config, path string, store secret.Store, token string) (*Manager, error) {
	if token == "" {
		token = config.RandomID()
	}
	m := &Manager{c: c, path: path, store: store, Token: token, secretErrors: map[string]string{}}
	for i := range c.Rules {
		p, e := store.Get(c.Rules[i].ID)
		if e != nil {
			// Never exit on a read failure: keep running with no password for this rule.
			m.secretErrors[c.Rules[i].ID] = e.Error()
			p = ""
		}
		c.Rules[i].Password = p
	}
	return m, nil
}

// SecretStatus describes passwords that could not be read, or "" if all were read.
func (m *Manager) SecretStatus() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.secretStatus()
}
func (m *Manager) secretStatus() string {
	if len(m.secretErrors) == 0 {
		return ""
	}
	var names, details []string
	for _, r := range m.c.Rules {
		if e, ok := m.secretErrors[r.ID]; ok {
			name := r.Name
			if name == "" {
				name = r.HostPrefix
			}
			names = append(names, name)
			details = append(details, e)
		}
	}
	sort.Strings(details)
	return fmt.Sprintf("无法读取 %d 条规则的密码（%s），这些规则暂按无密码处理：%s", len(names), joinUnique(names), joinUnique(details))
}
func joinUnique(v []string) string {
	seen := map[string]bool{}
	out := ""
	for _, s := range v {
		if seen[s] {
			continue
		}
		seen[s] = true
		if out != "" {
			out += "；"
		}
		out += s
	}
	return out
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
			if rerr := m.SetLaunchAtLogin(old); rerr != nil {
				err = fmt.Errorf("%w; rollback of launch at login failed: %v", err, rerr)
			}
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
		http.Error(w, "invalid Host", http.StatusForbidden)
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
		http.Error(w, "invalid Origin", http.StatusForbidden)
		return false
	}
	token := r.Header.Get("X-Auth-Token")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(m.Token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
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
		json.NewEncoder(w).Encode(map[string]any{"proxy_addr": m.c.Listen, "ca_path": m.CAPath, "system_proxy_enabled": m.enabled, "secret_error": m.secretStatus()})
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
				http.Error(w, "invalid preferences", http.StatusBadRequest)
				return
			}
			if err := m.updateLaunchAtLogin(*input.Launch); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write([]byte(`{"saved":true}`))
		default:
			w.Header().Set("Allow", "GET, PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	if r.URL.Path == "/api/domains" {
		switch r.Method {
		case "GET":
			domains := m.c.TrustedDomains
			if domains == nil {
				domains = []string{}
			}
			json.NewEncoder(w).Encode(map[string]any{"trusted_domains": domains})
		case "PUT":
			var input struct {
				Domains *[]string `json:"trusted_domains"`
			}
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&input); err != nil || input.Domains == nil || dec.Decode(new(any)) != io.EOF {
				http.Error(w, "invalid trusted_domains", http.StatusBadRequest)
				return
			}
			domains, err := config.NormalizeDomains(*input.Domains)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			next := *m.c
			next.TrustedDomains = domains
			if err := config.Save(m.path, &next); err != nil {
				http.Error(w, "config save failed", http.StatusInternalServerError)
				return
			}
			m.c = &next
			if m.Publish != nil {
				m.Publish(&next)
			}
			if m.Changed != nil {
				if err := m.Changed(); err != nil {
					http.Error(w, "saved; PAC refresh failed", http.StatusInternalServerError)
					return
				}
			}
			w.Write([]byte(`{"saved":true}`))
		default:
			w.Header().Set("Allow", "GET, PUT")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
			HasPassword   bool   `json:"has_password"`
			PasswordError string `json:"password_error,omitempty"`
		}
		rows := make([]view, 0, len(m.c.Rules))
		for _, v := range m.c.Rules {
			rows = append(rows, view{v, v.Password != "", m.secretErrors[v.ID]})
		}
		json.NewEncoder(w).Encode(rows)
	case "PUT":
		var rows []inputRule
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if e := dec.Decode(&rows); e != nil {
			http.Error(w, "invalid rules", http.StatusBadRequest)
			return
		}
		if dec.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid trailing JSON", http.StatusBadRequest)
			return
		}
		next := *m.c
		next.Rules = make([]config.Rule, len(rows))
		// old holds the stored passwords we know. Unreadable ones are not in it,
		// so a rollback never overwrites them with an empty value.
		old := map[string]string{}
		existing := map[string]bool{}
		for _, r := range m.c.Rules {
			existing[r.ID] = true
			if _, bad := m.secretErrors[r.ID]; !bad {
				old[r.ID] = r.Password
			}
		}
		// untouched lists unreadable rules whose password the user did not change;
		// their stored item is left as is.
		untouched := map[string]bool{}
		for i, row := range rows {
			v := row.Rule
			v.Password = old[v.ID]
			if row.ClearPassword {
				if row.Password != nil && *row.Password != "" {
					http.Error(w, "clear conflicts with password", http.StatusBadRequest)
					return
				}
				v.Password = ""
			} else if row.Password != nil && *row.Password != "" {
				v.Password = *row.Password
			} else if _, bad := m.secretErrors[v.ID]; bad {
				untouched[v.ID] = true
			}
			next.Rules[i] = v
		}
		if e := config.Validate(next.Rules); e != nil {
			http.Error(w, e.Error(), http.StatusBadRequest)
			return
		}
		// Roll back completed secret operations if persistence fails. Publish only after all writes succeed.
		restore := func() error {
			var errs []error
			for id, p := range old {
				if e := m.store.Set(id, p); e != nil {
					errs = append(errs, e)
				}
			}
			for _, r := range next.Rules {
				if !existing[r.ID] {
					if e := m.store.Delete(r.ID); e != nil {
						errs = append(errs, e)
					}
				}
			}
			return errors.Join(errs...)
		}
		fail := func(msg string, e error) {
			msg += ": " + e.Error()
			if re := restore(); re != nil {
				msg += "; rollback failed, stored passwords may be inconsistent: " + re.Error()
			}
			http.Error(w, msg, http.StatusInternalServerError)
		}
		for _, r := range next.Rules {
			if untouched[r.ID] {
				continue
			}
			if e := m.store.Set(r.ID, r.Password); e != nil {
				fail("secret save failed", e)
				return
			}
		}
		keep := map[string]bool{}
		for _, r := range next.Rules {
			keep[r.ID] = true
		}
		for id := range existing {
			if !keep[id] {
				if e := m.store.Delete(id); e != nil {
					fail("secret delete failed", e)
					return
				}
			}
		}
		if e := config.Save(m.path, &next); e != nil {
			fail("config save failed", e)
			return
		}
		m.c = &next
		for id := range m.secretErrors {
			if !untouched[id] {
				delete(m.secretErrors, id)
			}
		}
		if m.SecretsChanged != nil {
			m.SecretsChanged(m.secretStatus())
		}
		if m.Publish != nil {
			m.Publish(&next)
		}
		if m.Changed != nil {
			if e := m.Changed(); e != nil {
				http.Error(w, "saved; PAC refresh failed", http.StatusInternalServerError)
				return
			}
		}
		w.Write([]byte(`{"saved":true}`))
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
