//go:build !darwin

package secret

// New returns the platform secret store; outside macOS it is the file store.
func New(dir string) Store { return NewFile(dir) }
