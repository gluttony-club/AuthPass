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
	}{{"dev.", "DEV.foo.com:443", true}, {"dev.", "dev.a.b.cn", true}, {"dev.", "evildev.foo.com", false}, {"", "foo", false}, {"dev.", "dev", false}} {
		if Match(v.p, v.h) != v.want {
			t.Fatalf("%+v", v)
		}
	}
}
func TestRules(t *testing.T) {
	c := &Config{Rules: []Rule{{HostPrefix: "test.", Username: "first", Enabled: true}, {HostPrefix: "test.a", Username: "second", Enabled: true}}}
	if c.Target("test.a.com").Username != "first" {
		t.Fatal("order")
	}
	c.Rules[0].Username = ""
	if c.Target("test.a.com") != nil {
		t.Fatal("unconfigured first match")
	}
	for _, p := range []string{"", "*.foo", "UPPER.", "a/b"} {
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
