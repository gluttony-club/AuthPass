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
	"strings"
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
	// save persists the configuration; tests replace it to simulate failures.
	save func(string, *config.Config) error
}

func New(c *config.Config, path string, store secret.Store, token string) (*Manager, error) {
	if token == "" {
		token = config.RandomID()
	}
	m := &Manager{c: c, path: path, store: store, Token: token, secretErrors: map[string]string{}, save: config.Save}
	for i := range c.Rules {
		if c.Rules[i].PasswordReset {
			// The stored item may be stale; never read or use it.
			c.Rules[i].Password = ""
			continue
		}
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
	var names, details, reset []string
	for _, r := range m.c.Rules {
		name := r.Name
		if name == "" {
			name = r.HostPrefix
		}
		if e, ok := m.secretErrors[r.ID]; ok {
			names = append(names, name)
			details = append(details, e)
		} else if r.PasswordReset {
			reset = append(reset, name)
		}
	}
	var parts []string
	if len(names) > 0 {
		sort.Strings(details)
		parts = append(parts, fmt.Sprintf("无法读取 %d 条规则的密码（%s），这些规则暂不拦截：%s", len(names), joinUnique(names), joinUnique(details)))
	}
	if len(reset) > 0 {
		parts = append(parts, fmt.Sprintf("%d 条规则的密码需要重新输入（%s），这些规则暂不拦截", len(reset), joinUnique(reset)))
	}
	return strings.Join(parts, "；")
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
	if err := m.save(m.path, &next); err != nil {
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
			if err := m.save(m.path, &next); err != nil {
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
		// old holds the stored passwords we know. Unreadable and ignored
		// (PasswordReset) ones are not in it, so a rollback never touches them.
		old := map[string]string{}
		existing := map[string]bool{}
		marked := map[string]bool{}
		for _, r := range m.c.Rules {
			existing[r.ID] = true
			marked[r.ID] = r.PasswordReset
			if _, bad := m.secretErrors[r.ID]; !bad && !r.PasswordReset {
				old[r.ID] = r.Password
			}
		}
		// untouched lists unreadable rules whose password the user did not change;
		// their stored item is left as is.
		untouched := map[string]bool{}
		// clearIgnored lists rules with PasswordReset whose ignored item the
		// user asked to clear; that delete is deferred like the others.
		clearIgnored := map[string]bool{}
		for i, row := range rows {
			v := row.Rule
			v.PasswordReset = marked[v.ID] // never taken from the client
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
			if v.PasswordReset && v.Password == "" {
				if row.ClearPassword {
					clearIgnored[v.ID] = true
				} else {
					// Still no new password: leave the ignored item alone.
					untouched[v.ID] = true
				}
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
		keep := map[string]bool{}
		for _, r := range next.Rules {
			keep[r.ID] = true
		}
		// The original password of an unreadable rule can never be restored by a
		// rollback, so its keychain item is only changed (set, cleared or
		// deleted) after the configuration has been saved. Until that change is
		// confirmed the rule is saved with PasswordReset, so a failed change can
		// never leave the old password in use with the new settings (or bring
		// back a cleared password) after a restart. Items of removed rules whose
		// stored password is already ignored are also deleted afterwards, so a
		// failure there does not block saving.
		deferred := map[string]bool{}
		for id := range m.secretErrors {
			if existing[id] && !untouched[id] {
				deferred[id] = true
			}
		}
		for id := range marked {
			if marked[id] && (!keep[id] || clearIgnored[id]) {
				deferred[id] = true
			}
		}
		for i := range next.Rules {
			r := &next.Rules[i]
			if untouched[r.ID] {
				continue
			}
			if deferred[r.ID] {
				r.PasswordReset = true
				continue
			}
			if e := m.store.Set(r.ID, r.Password); e != nil {
				fail("secret save failed", e)
				return
			}
			r.PasswordReset = false
		}
		for id := range existing {
			if !keep[id] && !deferred[id] {
				if e := m.store.Delete(id); e != nil {
					fail("secret delete failed", e)
					return
				}
			}
		}
		if e := m.save(m.path, &next); e != nil {
			fail("config save failed", e)
			return
		}
		// The configuration is saved; now apply the deferred changes. A rule
		// whose change fails keeps PasswordReset and does not intercept until
		// its password is entered again.
		var pending []string
		var confirmed []int
		for i := range next.Rules {
			r := &next.Rules[i]
			if !deferred[r.ID] {
				continue
			}
			if e := m.store.Set(r.ID, r.Password); e != nil {
				r.Password = ""
				var re *secret.ReplaceError
				if errors.As(e, &re) {
					pending = append(pending, fmt.Sprintf("rule %q: the old keychain item was deleted, but the new password could not be saved (%v); the rule will not intercept until its password is entered again", r.ID, e))
				} else {
					pending = append(pending, fmt.Sprintf("rule %q: the keychain item was left unchanged (%v) and will not be used; the rule will not intercept until its password is entered again", r.ID, e))
				}
				continue
			}
			r.PasswordReset = false
			confirmed = append(confirmed, i)
		}
		for id := range deferred {
			if !keep[id] {
				if e := m.store.Delete(id); e != nil {
					pending = append(pending, fmt.Sprintf("removed rule %q: the keychain item could not be deleted and was left in place, unused (%v)", id, e))
				}
			}
		}
		if len(confirmed) > 0 {
			if e := m.save(m.path, &next); e != nil {
				// The saved configuration still ignores these items; match it.
				for _, i := range confirmed {
					r := &next.Rules[i]
					r.PasswordReset = true
					r.Password = ""
					pending = append(pending, fmt.Sprintf("rule %q: the password was saved to the keychain, but the configuration could not be updated (%v); the rule will not intercept until its password is entered again", r.ID, e))
				}
			}
		}
		m.c = &next
		for id := range m.secretErrors {
			if !untouched[id] || !keep[id] {
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
		if len(pending) > 0 {
			sort.Strings(pending)
			http.Error(w, "rules saved, but some keychain changes failed: "+strings.Join(pending, "; "), http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"saved":true}`))
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
