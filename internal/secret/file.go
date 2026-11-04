package secret

import (
	"encoding/json"
	"github.com/gluttony-club/AuthPass/internal/config"
	"os"
	"path/filepath"
	"sync"
)

type fileStore struct {
	path string
	mu   sync.Mutex
}

// NewFile returns a plaintext JSON store (0600). Used on non-macOS and in tests.
func NewFile(dir string) Store { return &fileStore{path: filepath.Join(dir, "secrets.json")} }
func (s *fileStore) read() (map[string]string, error) {
	m := map[string]string{}
	b, e := os.ReadFile(s.path)
	if os.IsNotExist(e) {
		return m, nil
	}
	if e != nil {
		return nil, e
	}
	e = json.Unmarshal(b, &m)
	return m, e
}
func (s *fileStore) Get(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, e := s.read()
	return m[id], e
}
func (s *fileStore) change(id, p string, del bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, e := s.read()
	if e != nil {
		return e
	}
	if del {
		delete(m, id)
	} else {
		m[id] = p
	}
	b, e := json.Marshal(m)
	if e != nil {
		return e
	}
	return config.WriteFile(s.path, b)
}
func (s *fileStore) Set(id, p string) error { return s.change(id, p, false) }
func (s *fileStore) Delete(id string) error { return s.change(id, "", true) }
