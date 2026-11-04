//go:build darwin && cgo

package secret

import (
	"fmt"
	"testing"

	kc "github.com/keybase/go-keychain"
)

// These tests only classify error codes; they never touch the real keychain.
func TestRecoverable(t *testing.T) {
	for _, v := range []struct {
		err  error
		want bool
	}{
		{errSecInvalidOwnerEdit, true},
		{kc.Error(-25244), true},
		{fmt.Errorf("wrapped: %w", errSecInvalidOwnerEdit), true},
		{kc.ErrorAuthFailed, false}, // errSecAuthFailed (-25293), e.g. Deny
		{kc.Error(-25293), false},
		{fmt.Errorf("wrapped: %w", kc.ErrorAuthFailed), false},
		{nil, false},
		{kc.Error(-128), false}, // errSecUserCanceled
		{fmt.Errorf("wrapped: %w", kc.Error(-128)), false},
		{kc.ErrorInteractionNotAllowed, false},
		{kc.ErrorNoAccessForItem, false},
		{kc.ErrorItemNotFound, false},
		{fmt.Errorf("other"), false},
	} {
		if got := recoverable(v.err); got != v.want {
			t.Errorf("recoverable(%v) = %v, want %v", v.err, got, v.want)
		}
	}
}
