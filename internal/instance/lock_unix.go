//go:build unix

package instance

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Lock takes an exclusive per-user lock in dir that is held until the returned
// Closer is closed or the process exits. It does not depend on the
// configuration, so it is taken before the config is loaded and before any
// system proxy state is touched. ErrAlreadyRunning means another instance
// holds it.
func Lock(dir string) (io.Closer, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "instance.lock"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrAlreadyRunning
		}
		return nil, err
	}
	return f, nil
}
