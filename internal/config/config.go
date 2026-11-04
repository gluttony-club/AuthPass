package config

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed default_config.json
var Default []byte

type Rule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	HostPrefix string `json:"host_prefix"`
	Username   string `json:"username"`
	Password   string `json:"-"`
	Enabled    bool   `json:"enabled"`
}
type Config struct {
	LaunchAtLoginValue         *bool             `json:"launch_at_login"`
	Listen                     string            `json:"listen"`
	PACPath                    string            `json:"pac_path"`
	AutoEnable                 bool              `json:"auto_enable"`
	Rules                      []Rule            `json:"rules"`
	InsecureSkipVerifyUpstream bool              `json:"insecure_skip_verify_upstream"`
	UpstreamCAFile             string            `json:"upstream_ca_file"`
	HostOverrides              map[string]string `json:"host_overrides,omitempty"`
}

func RandomID() string {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func DataDir() (string, error) {
	d, e := os.UserConfigDir()
	return filepath.Join(d, "BasicAuthHelper"), e
}
func Load(path string) (*Config, error) {
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		b = Default
	} else if e != nil {
		return nil, e
	}
	c := &Config{Listen: "127.0.0.1:18080", PACPath: "/proxy.pac", AutoEnable: true}
	if e = json.Unmarshal(b, c); e != nil {
		return nil, e
	}
	h, _, e := net.SplitHostPort(c.Listen)
	if e != nil || (h != "127.0.0.1" && h != "localhost") {
		return nil, fmt.Errorf("listen must be loopback host:port")
	}
	if !strings.HasPrefix(c.PACPath, "/") || c.PACPath == "/settings" || c.PACPath == "/status" || c.PACPath == "/__basicauth_helper_ping" || strings.HasPrefix(c.PACPath, "/api/") {
		return nil, fmt.Errorf("invalid pac_path")
	}
	if e = Validate(c.Rules); e != nil {
		return nil, e
	}
	if _, e = os.Stat(path); os.IsNotExist(e) {
		if e = Save(path, c); e != nil {
			return nil, e
		}
	}
	return c, nil
}

var prefixRE = regexp.MustCompile(`^[a-z0-9.-]+$`)
var idRE = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func Validate(rules []Rule) error {
	ids := map[string]bool{}
	for i := range rules {
		r := &rules[i]
		if r.ID == "" {
			r.ID = RandomID()
		}
		if !idRE.MatchString(r.ID) || ids[r.ID] {
			return fmt.Errorf("invalid or duplicate rule id")
		}
		ids[r.ID] = true
		if !prefixRE.MatchString(r.HostPrefix) {
			return fmt.Errorf("host_prefix must contain only [a-z0-9.-] and be non-empty")
		}
	}
	return nil
}
func Save(path string, c *Config) error {
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	return WriteFile(path, b)
}
func WriteFile(path string, b []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".config-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func Host(s string) string {
	if h, _, e := net.SplitHostPort(s); e == nil {
		s = h
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(s, "[]"), "."))
}
func Match(prefix, host string) bool { return prefix != "" && strings.HasPrefix(Host(host), prefix) }
func (c *Config) Target(host string) *Rule {
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.Enabled && Match(r.HostPrefix, host) {
			if r.Username == "" {
				return nil
			}
			return r
		}
	}
	return nil
}

func (c *Config) LaunchAtLogin() bool { return c.LaunchAtLoginValue == nil || *c.LaunchAtLoginValue }
