package secret

// Store keeps passwords separate from the public configuration.
type Store interface {
	Get(id string) (string, error)
	Set(id, password string) error
	Delete(id string) error
}
