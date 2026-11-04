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
		{kc.ErrorAuthFailed, true},
		{fmt.Errorf("wrapped: %w", kc.ErrorAuthFailed), true},
		{nil, false},
		{kc.Error(-128), false}, // errSecUserCanceled
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
