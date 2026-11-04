package instance

import (
	"errors"
	"net/http"
	"testing"
)

func TestListen(t *testing.T) {
	for _, own := range []bool{false, true} {
		ln, err := Listen("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if own && r.URL.Path == PingPath {
				w.Write([]byte(Identity))
			} else {
				w.Write([]byte("other"))
			}
		})}
		go srv.Serve(ln)
		second, err := Listen(ln.Addr().String())
		if second != nil {
			second.Close()
			t.Fatal("duplicate listener")
		}
		if err == nil || errors.Is(err, ErrAlreadyRunning) != own {
			t.Fatal(err, own)
		}
		srv.Close()
	}
}
