//go:build darwin && cgo

package secret

import (
	"errors"
	"fmt"
	"os/exec"

	kc "github.com/keybase/go-keychain"
)

type keychain struct{}

func New(dir string) Store { return keychain{} }

// errSecInvalidOwnerEdit is returned when the item's access control belongs to
// a different code signature (for example an older, ad-hoc signed build).
const errSecInvalidOwnerEdit kc.Error = -25244

// recoverable reports whether err means the item belongs to another build and
// may be replaced. Only errSecInvalidOwnerEdit qualifies. Every other error,
// including errSecAuthFailed (-25293, which a denied keychain prompt may
// return) and errSecUserCanceled (-128), is returned and the existing item is
// never deleted.
func recoverable(err error) bool {
	var code kc.Error
	return errors.As(err, &code) && code == errSecInvalidOwnerEdit
}

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
		if recoverable(err) {
			// Item owned by another build (e.g. older version or re-signed app):
			// remove it and add a fresh one owned by this app.
			if err = forceDelete(id); err == nil {
				err = kc.AddItem(item)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("keychain operation failed: %w", err)
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
		return "", fmt.Errorf("keychain operation failed: %w", err)
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
	if recoverable(err) {
		err = forceDelete(id)
	}
	if err != nil {
		return fmt.Errorf("keychain operation failed: %w", err)
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
		return fmt.Errorf("keychain delete failed: %v: %s", err, out)
	}
	return nil
}
