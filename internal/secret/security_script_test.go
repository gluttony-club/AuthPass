package secret

import (
	"strings"
	"testing"
)

func TestSecuritySetScript(t *testing.T) {
	password := "secret '\"\\\n密码\x00"
	script, err := securitySetScript("Rule_1-test", password)
	if err != nil {
		t.Fatal(err)
	}
	want := "add-generic-password -U -s club.gluttony.authpass -a Rule_1-test -X 7365637265742027225c0ae5af86e7a08100\n"
	if script != want {
		t.Fatalf("unexpected script: %q", script)
	}
	if strings.Contains(script, password) {
		t.Fatal("plaintext password in script")
	}
}

func TestSecuritySetScriptRejectsInvalidIDs(t *testing.T) {
	for _, id := range []string{"", "a b", "a\nquit", "a;quit", "a'", "a\"", "a\\", "密码"} {
		t.Run(id, func(t *testing.T) {
			script, err := securitySetScript(id, "secret")
			if err == nil || script != "" {
				t.Fatal("invalid ID accepted")
			}
		})
	}
}

func TestSecuritySetScriptEmptyPassword(t *testing.T) {
	// Set maps an empty password to delete, so the script builder refuses it.
	if script, err := securitySetScript("rule", ""); err == nil || script != "" {
		t.Fatalf("empty password accepted: %q", script)
	}
}
