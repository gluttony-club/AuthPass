//go:build !unix

package instance

import "io"

type noLock struct{}

func (noLock) Close() error { return nil }

// Lock is a no-op on platforms without flock; Listen still detects a running instance.
func Lock(dir string) (io.Closer, error) { return noLock{}, nil }
