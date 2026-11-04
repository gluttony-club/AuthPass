package secret

import "fmt"

// ReplaceError is returned by Set when the existing item belonged to another
// build and had to be deleted, but writing the new item then failed. Unlike
// any other Set error, the previously stored password is gone.
type ReplaceError struct{ Err error }

func (e *ReplaceError) Error() string {
	return fmt.Sprintf("the existing keychain item was deleted but the new password could not be saved: %v", e.Err)
}
func (e *ReplaceError) Unwrap() error { return e.Err }

// setItem implements add-or-update. add reports duplicate via isDuplicate;
// an update error accepted by replaceable deletes the item and adds it again.
// If that delete succeeds and the add fails, the result is a *ReplaceError;
// every other error leaves the existing item in place.
func setItem(add, update, remove func() error, isDuplicate, replaceable func(error) bool) error {
	err := add()
	if err == nil || !isDuplicate(err) {
		return err
	}
	err = update()
	if err == nil || !replaceable(err) {
		return err
	}
	if err = remove(); err != nil {
		return err
	}
	if err = add(); err != nil {
		return &ReplaceError{Err: err}
	}
	return nil
}
