package secret

import (
	"encoding/hex"
	"fmt"
	"regexp"
)

const service = "club.gluttony.authpass"

var securityAccountID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// securitySetScript keeps password bytes out of argv and shell-style quoting.
func securitySetScript(id, password string) (string, error) {
	if !securityAccountID.MatchString(id) {
		return "", fmt.Errorf("invalid account ID")
	}
	if password == "" {
		return "", fmt.Errorf("empty password")
	}
	encoded := hex.EncodeToString([]byte(password))
	return fmt.Sprintf("add-generic-password -U -s %s -a %s -X %s\n", service, id, encoded), nil
}
