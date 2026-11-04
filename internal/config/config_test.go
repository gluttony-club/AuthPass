package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMatch(t *testing.T) {
	for _, v := range []struct {
		p, h string
		want bool
	}{{"dev.", "DEV.example.com:443", true}, {"dev.", "dev.a.example.net", true}, {"dev.", "evildev.example.com", false}, {"", "foo", false}, {"dev.", "dev", false}} {
		if Match(v.p, v.h) != v.want {
			t.Fatalf("%+v", v)
		}
	}
}
func TestRules(t *testing.T) {
	c := &Config{TrustedDomains: []string{"example.com"}, Rules: []Rule{{HostPrefix: "test.", Username: "first", Enabled: true}, {HostPrefix: "test.example.", Username: "second", Enabled: true}}}
	if c.Target("test.example.com").Username != "first" {
		t.Fatal("order")
	}
	c.Rules[0].Username = ""
	if c.Target("test.example.com") != nil {
		t.Fatal("unconfigured first match")
	}
	for _, p := range []string{"", "*.example.com", "a/b"} {
		if Validate([]Rule{{HostPrefix: p}}) == nil {
			t.Fatal(p)
		}
	}
}
func TestDefaultsAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Rules) != 0 {
		t.Fatal(c)
	}
	c.Rules = []Rule{{ID: "dev", Name: "开发环境", HostPrefix: "dev.", Enabled: true}}
	c.Rules[0].Password = "secret-test"
	c.Rules[0].Name = "changed"
	if e = Save(path, c); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "secret-test") || strings.Contains(string(b), "password") {
		t.Fatal(string(b))
	}
	c, e = Load(path)
	if e != nil || c.Rules[0].Name != "changed" {
		t.Fatal(c, e)
	}
}

func TestLaunchAtLogin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	for _, field := range []string{"", `,"launch_at_login":null`, `,"launch_at_login":false`, `,"launch_at_login":true`} {
		if err := os.WriteFile(path, []byte(`{"listen":"127.0.0.1:18080","pac_path":"/proxy.pac"`+field+`}`), 0600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		want := !strings.Contains(field, "false")
		if c.LaunchAtLogin() != want {
			t.Fatal(field)
		}
		value := c.LaunchAtLogin()
		c.LaunchAtLoginValue = &value
		if err := Save(path, c); err != nil {
			t.Fatal(err)
		}
		c, err = Load(path)
		if err != nil || c.LaunchAtLogin() != want || c.LaunchAtLoginValue == nil {
			t.Fatal(c, err)
		}
	}
}

func TestTrustedDomains(t *testing.T) {
	c := &Config{TrustedDomains: []string{"example.com", "example.net"}, Rules: []Rule{{HostPrefix: " DEV. ", Username: "user", Enabled: true}}}
	if err := Validate(c.Rules); err != nil || c.Rules[0].HostPrefix != "dev." {
		t.Fatal(c, err)
	}
	for _, host := range []string{"dev.example.com", "DEV.Example.COM.", "dev.example.com:443", "dev.a.example.net", "[dev.example.com]:443"} {
		if c.Target(host) == nil {
			t.Errorf("did not match %s", host)
		}
	}
	for _, host := range []string{"dev.evil.com", "dev.example.com.evil.com", "devexample.com", "dev.notexample.com"} {
		if c.Target(host) != nil {
			t.Errorf("matched %s", host)
		}
	}
	if !c.Trusted("example.com") {
		t.Fatal("root domain not trusted")
	}
	c.TrustedDomains = nil
	if c.Target("dev.example.com") != nil {
		t.Fatal("empty domains matched")
	}
}

func TestNormalizeDomains(t *testing.T) {
	domains, err := NormalizeDomains([]string{" Example.COM ", "", "example.com", " EXAMPLE.net "})
	if err != nil || strings.Join(domains, ",") != "example.com,example.net" {
		t.Fatal(domains, err)
	}
	for _, domain := range []string{"*.example.com", ".example.com", "example.com.", "localhost", "exa_mple.com", "example..com"} {
		if _, err := NormalizeDomains([]string{domain}); err == nil {
			t.Errorf("accepted %s", domain)
		}
	}
	path := filepath.Join(t.TempDir(), "config.json")
	for _, value := range []string{`[" EXAMPLE.COM ","example.com"]`, `["*.example.com"]`} {
		if err := os.WriteFile(path, []byte(`{"listen":"127.0.0.1:18080","pac_path":"/proxy.pac","trusted_domains":`+value+`}`), 0600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if strings.Contains(value, "*") {
			if err == nil {
				t.Fatal("invalid domains loaded")
			}
		} else if err != nil || len(c.TrustedDomains) != 1 || c.TrustedDomains[0] != "example.com" {
			t.Fatal(c, err)
		}
	}
}

func TestNonASCIIHostsNeverMatch(t *testing.T) {
	c := &Config{TrustedDomains: []string{"internal.test"}, Rules: []Rule{{HostPrefix: "dev.", Username: "user", Password: "secret", Enabled: true}}}
	if c.Target("dev.internal.test") == nil {
		t.Fatal("ASCII host did not match")
	}
	// strings.ToLower("İ") == "i̇" and strings.ToLower("K" Kelvin sign) == "k": such
	// hosts must not be treated as the ASCII names they fold to.
	for _, host := range []string{"dev.İnternal.test", "dev.\u0130nternal.test:443", "dev.internal.tes\u212A", "\u212Aey.internal.test", "dev.internal.test\u3002", "[dev.İnternal.test]:443", "dev.ınternal.test"} {
		if c.Target(host) != nil || c.Trusted(host) || Match("dev.", host) || Host(host) != "" {
			t.Errorf("non-ASCII host %q matched", host)
		}
	}
	for _, domain := range []string{"\u212Aexample.com", "exämple.com", "example.co\u0130"} {
		if _, err := NormalizeDomains([]string{domain}); err == nil {
			t.Errorf("accepted non-ASCII domain %q", domain)
		}
	}
	if err := Validate([]Rule{{HostPrefix: "\u212Aey."}}); err == nil {
		t.Fatal("accepted non-ASCII host_prefix")
	}
}

func TestNormalizeDomainsRejectsIPs(t *testing.T) {
	for _, domain := range []string{"127.0.0.1", "10.0.0.1", "0.1", "example.123", "192.168.1", "::1", "[::1]", "fe80::1"} {
		_, err := NormalizeDomains([]string{domain})
		if err == nil {
			t.Errorf("accepted %s", domain)
		} else if strings.Contains(domain, ".") && !strings.Contains(err.Error(), "IP addresses") {
			t.Errorf("unclear error for %s: %v", domain, err)
		}
	}
	for _, domain := range []string{"example.com", "1password.example", "a1.b2", "123.example.org"} {
		if _, err := NormalizeDomains([]string{domain}); err != nil {
			t.Errorf("rejected %s: %v", domain, err)
		}
	}
}
