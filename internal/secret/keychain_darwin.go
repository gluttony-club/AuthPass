//go:build darwin && cgo

package secret

import (
	"fmt"
	"os/exec"

	kc "github.com/keybase/go-keychain"
)

type keychain struct{}

func New(dir string) Store { return keychain{} }

func keychainQuery(id string) kc.Item {
	item := kc.NewItem()
	item.SetSecClass(kc.SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount(id)
	return item
}

func (keychain) Set(id, password string) error {
	item := keychainQuery(id)
	item.SetData([]byte(password))
	item.SetLabel("AuthPass")
	item.SetAccessible(kc.AccessibleWhenUnlocked)
	err := kc.AddItem(item)
	if err == kc.ErrorDuplicateItem {
		update := kc.NewItem()
		update.SetData([]byte(password))
		err = kc.UpdateItem(keychainQuery(id), update)
		if err != nil {
			// Item owned by another build (e.g. older version or re-signed app):
			// remove it and add a fresh one owned by this app.
			if forceDelete(id) == nil {
				err = kc.AddItem(item)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("Keychain operation failed: %w", err)
	}
	return nil
}

func (keychain) Get(id string) (string, error) {
	query := keychainQuery(id)
	query.SetMatchLimit(kc.MatchLimitOne)
	query.SetReturnData(true)
	results, err := kc.QueryItem(query)
	if err == kc.ErrorItemNotFound {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("Keychain operation failed: %w", err)
	}
	if len(results) == 0 {
		return "", nil
	}
	return string(results[0].Data), nil
}

func (keychain) Delete(id string) error {
	err := kc.DeleteItem(keychainQuery(id))
	if err == kc.ErrorItemNotFound {
		return nil
	}
	if err != nil {
		err = forceDelete(id)
	}
	if err != nil {
		return fmt.Errorf("Keychain operation failed: %w", err)
	}
	return nil
}

// forceDelete removes an item via the security tool, which can delete items
// whose access control belongs to a different binary. No secret is passed.
func forceDelete(id string) error {
	if !securityAccountID.MatchString(id) {
		return fmt.Errorf("invalid keychain account %q", id)
	}
	out, err := exec.Command("/usr/bin/security", "delete-generic-password", "-s", service, "-a", id).CombinedOutput()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 44 {
			return nil // not found
		}
		return fmt.Errorf("Keychain delete failed: %v: %s", err, out)
	}
	return nil
}
