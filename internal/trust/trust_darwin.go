//go:build darwin

package trust

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func Ensure(path string) error {
	if exec.Command("security", "verify-cert", "-c", path).Run() == nil {
		return nil
	}
	h, e := os.UserHomeDir()
	if e != nil {
		return e
	}
	b, e := exec.Command("security", "add-trusted-cert", "-r", "trustRoot", "-k", filepath.Join(h, "Library/Keychains/login.keychain-db"), path).CombinedOutput()
	if e != nil {
		return fmt.Errorf("trust CA: %w: %s", e, b)
	}
	return nil
}
func Uninstall() error {
	h, e := os.UserHomeDir()
	if e != nil {
		return e
	}
	return exec.Command("security", "delete-certificate", "-c", "AuthPass Local CA", filepath.Join(h, "Library/Keychains/login.keychain-db")).Run()
}
