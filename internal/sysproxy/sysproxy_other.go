//go:build !darwin

package sysproxy

import "fmt"

func Enable(dir, url string) error { return fmt.Errorf("system proxy is supported only on macOS") }
func Restore(dir string) error     { return nil }
