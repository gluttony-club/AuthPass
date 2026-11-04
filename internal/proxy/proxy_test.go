package proxy

import (
	"github.com/gluttony-club/AuthPass/internal/ca"
	"github.com/gluttony-club/AuthPass/internal/config"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestPAC(t *testing.T) {
	c := &config.Config{Listen: "127.0.0.1:18080", Rules: []config.Rule{{HostPrefix: "dev.", Username: "user", Enabled: true}, {HostPrefix: "staging.", Enabled: true}}}
	p := PAC(c)
	for _, v := range []string{`shExpMatch(host, "dev.*")`, `PROXY 127.0.0.1:18080`, `return "DIRECT"`} {
		if !strings.Contains(p, v) {
			t.Fatal(p)
		}
	}
}
func TestProxy(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials leaked upstream")
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "demo" || p != "demo123" {
			w.WriteHeader(401)
		}
		_, _ = io.WriteString(w, r.Header.Get("Authorization"))
	})
	plain := httptest.NewServer(h)
	defer plain.Close()
	upstreamCA, e := ca.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	upstreamCert, e := upstreamCA.Certificate("test.foo.test")
	if e != nil {
		t.Fatal(e)
	}
	secure := httptest.NewUnstartedServer(h)
	secure.TLS = &tls.Config{Certificates: []tls.Certificate{*upstreamCert}}
	secure.StartTLS()
	defer secure.Close()
	a, e := ca.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	b, _ := os.ReadFile(a.CertPath)
	pool.AppendCertsFromPEM(b)
	upstreamPEM, _ := os.ReadFile(upstreamCA.CertPath)
	pool.AppendCertsFromPEM(upstreamPEM)
	c := &config.Config{Listen: "127.0.0.1:18080", PACPath: "/proxy.pac", Rules: []config.Rule{{HostPrefix: "test.", Username: "demo", Password: "demo123", Enabled: true}}, HostOverrides: map[string]string{"test.foo.test": "127.0.0.1", "other.local": "127.0.0.1"}}
	// Verify the upstream hostname and chain normally, using our test CA.
	c.UpstreamCAFile = upstreamCA.CertPath
	p, e := New(c, a)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	ps := httptest.NewServer(p)
	defer ps.Close()
	pu, _ := url.Parse(ps.URL)
	tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	for _, scheme := range []string{"http", "https"} {
		base := plain.URL
		if scheme == "https" {
			base = secure.URL
		}
		u, _ := url.Parse(base)
		_, port, _ := net.SplitHostPort(u.Host)
		for _, host := range []string{"test.foo.test", "other.local"} {
			// Verify the known upstream certificate while preserving the non-target CONNECT host.
			tr.TLSClientConfig.ServerName = ""
			if host == "other.local" {
				tr.TLSClientConfig.ServerName = "test.foo.test"
			}
			req, _ := http.NewRequest("GET", scheme+"://"+net.JoinHostPort(host, port)+"/", nil)
			if host == "test.foo.test" {
				req.SetBasicAuth("wrong", "wrong") // Target credentials must overwrite existing auth.
			}
			if scheme == "http" || host == "test.foo.test" {
				req.Header.Set("Proxy-Authorization", "must-not-leak")
			}
			resp, e := client.Do(req)
			if e != nil {
				t.Fatal(e)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			want := 200
			if host == "other.local" {
				want = 401
				if len(body) != 0 {
					t.Fatalf("non-target received auth: %s", body)
				}
			}
			if resp.StatusCode != want {
				t.Fatalf("%s %s: %d", scheme, host, resp.StatusCode)
			}
			if scheme == "https" {
				cert := resp.TLS.PeerCertificates[0]
				if host == "other.local" {
					if !cert.Equal(secure.Certificate()) {
						t.Fatal("non-target was intercepted")
					}
				} else if cert.Issuer.CommonName != ca.Name {
					t.Fatal("target not intercepted")
				}
			}
		}
	}
}

func TestPACUnconfiguredAndOrdering(t *testing.T) {
	c := &config.Config{Listen: "127.0.0.1:18080", Rules: []config.Rule{
		{HostPrefix: "staging.", Enabled: true},
		{HostPrefix: "test.", Enabled: true},
		{HostPrefix: "test.feature.", Username: "user", Enabled: true},
		{HostPrefix: "disabled.", Username: "user", Enabled: false},
	}}
	p := PAC(c)
	if strings.Contains(p, "staging.") || strings.Contains(p, "disabled.") {
		t.Fatal(p)
	}
	if !strings.Contains(p, `!shExpMatch(host, "test.*")`) {
		t.Fatal("first unconfigured match must remain DIRECT", p)
	}
}

func TestAtomicReload(t *testing.T) {
	c := &config.Config{Listen: "127.0.0.1:18080", PACPath: "/proxy.pac"}
	p, e := New(c, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			next := *c
			next.Rules = []config.Rule{{HostPrefix: "feature.", Username: "user", Enabled: true}}
			p.Update(&next)
		}
	}()
	for i := 0; i < 100; i++ {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, httptest.NewRequest("GET", "/proxy.pac", nil))
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-cache" {
			t.Fatal(w)
		}
	}
	<-done
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "/proxy.pac", nil))
	if !strings.Contains(w.Body.String(), "feature.*") {
		t.Fatal(w.Body)
	}
	w = httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1:18080/settings?token=test", nil))
	if w.Code != 403 {
		t.Fatal("proxy request reached settings", w.Code)
	}
}
