//go:build !darwin

package trust

import "fmt"

func Ensure(string) error { return fmt.Errorf("install the CA manually on this platform") }
func Uninstall() error    { return fmt.Errorf("remove the CA manually on this platform") }
