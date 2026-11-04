//go:build darwin && cgo

package secret

import (
	"fmt"

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
		return fmt.Errorf("Keychain operation failed: %w", err)
	}
	return nil
}
