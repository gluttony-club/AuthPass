//go:build darwin

package secret

import (
	"fmt"
	"os/exec"
	"strings"
)

const service = "com.example.basicauthhelper"

type keychain struct{}

func New(dir string) Store { return keychain{} }
func run(args ...string) (string, error) {
	b, e := exec.Command("/usr/bin/security", args...).Output()
	if e != nil {
		if x, ok := e.(*exec.ExitError); ok && x.ExitCode() == 44 && args[0] != "add-generic-password" {
			return "", nil
		}
		return "", fmt.Errorf("Keychain operation failed: %w", e)
	}
	return strings.TrimSuffix(string(b), "\n"), nil
}
func (keychain) Get(id string) (string, error) {
	return run("find-generic-password", "-s", service, "-a", id, "-w")
}
func (keychain) Set(id, p string) error {
	_, e := run("add-generic-password", "-U", "-s", service, "-a", id, "-w", p)
	return e
}
func (keychain) Delete(id string) error {
	_, e := run("delete-generic-password", "-s", service, "-a", id)
	return e
}
