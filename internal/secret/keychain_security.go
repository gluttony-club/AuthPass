//go:build darwin && !cgo

package secret

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

type keychain struct{}

func New(dir string) Store { return keychain{} }

func (keychain) Set(id, password string) error {
	if password == "" {
		// An absent item reads back as "", so deleting avoids an empty -X argument.
		_, err := securityRun("delete-generic-password", id)
		return err
	}
	script, err := securitySetScript(id, password)
	if err != nil {
		return fmt.Errorf("keychain operation failed: %w", err)
	}
	cmd := exec.Command("/usr/bin/security", "-i")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keychain operation failed: %w", err)
	}
	if strings.TrimSpace(stderr.String()) != "" {
		return fmt.Errorf("keychain operation failed: security command failed")
	}
	return nil
}

func securityRun(operation, id string) (string, error) {
	if !securityAccountID.MatchString(id) {
		return "", fmt.Errorf("keychain operation failed: invalid account ID")
	}
	args := []string{operation, "-s", service, "-a", id}
	if operation == "find-generic-password" {
		args = append(args, "-w")
	}
	b, err := exec.Command("/usr/bin/security", args...).Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 44 {
			return "", nil
		}
		return "", fmt.Errorf("keychain operation failed: %w", err)
	}
	return strings.TrimSuffix(string(b), "\n"), nil
}

func (keychain) Get(id string) (string, error) {
	return securityRun("find-generic-password", id)
}

func (keychain) Delete(id string) error {
	_, err := securityRun("delete-generic-password", id)
	return err
}
