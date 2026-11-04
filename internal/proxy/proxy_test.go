package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/gluttony-club/AuthPass/internal/ca"
	"github.com/gluttony-club/AuthPass/internal/config"
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
	c := &config.Config{TrustedDomains: []string{"foo.test", "example.com"}, Listen: "127.0.0.1:18080", Rules: []config.Rule{{HostPrefix: "dev.", Username: "user", Enabled: true}, {HostPrefix: "staging.", Enabled: true}}}
	p := PAC(c)
	for _, v := range []string{`shExpMatch(host, "dev.*")`, `PROXY 127.0.0.1:18080`, `return "DIRECT"`, `host == "example.com" || dnsDomainIs(host, ".example.com")`, `host.toLowerCase()`} {
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
	c := &config.Config{TrustedDomains: []string{"foo.test", "example.com"}, Listen: "127.0.0.1:18080", PACPath: "/proxy.pac", Rules: []config.Rule{{HostPrefix: "test.", Username: "demo", Password: "demo123", AllowHTTP: true, Enabled: true}}, HostOverrides: map[string]string{"test.foo.test": "127.0.0.1", "other.test": "127.0.0.1"}}
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
		for _, host := range []string{"test.foo.test", "other.test"} {
			// Verify the known upstream certificate while preserving the non-target CONNECT host.
			tr.TLSClientConfig.ServerName = ""
			if host == "other.test" {
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
			if host == "other.test" {
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
				if host == "other.test" {
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
	c := &config.Config{TrustedDomains: []string{"foo.test", "example.com"}, Listen: "127.0.0.1:18080", Rules: []config.Rule{
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
	c := &config.Config{TrustedDomains: []string{"foo.test", "example.com"}, Listen: "127.0.0.1:18080", PACPath: "/proxy.pac"}
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

func TestEmptyDomainsPAC(t *testing.T) {
	c := &config.Config{Listen: "127.0.0.1:18080", Rules: []config.Rule{{HostPrefix: "dev.", Username: "user", Enabled: true}}}
	if p := PAC(c); strings.Contains(p, "PROXY") {
		t.Fatal(p)
	}
}

func TestHTTPOptIn(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.Header.Get("Authorization")) }))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	c := &config.Config{Listen: "127.0.0.1:18080", TrustedDomains: []string{"example.com"}, Rules: []config.Rule{{HostPrefix: "dev.", Username: "user", Password: "secret", Enabled: true}}, HostOverrides: map[string]string{"dev.example.com": "127.0.0.1", "dev.example.com.evil.test": "127.0.0.1"}}
	p, err := New(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, allow := range []bool{false, true} {
		next := *c
		next.Rules = append([]config.Rule(nil), c.Rules...)
		next.Rules[0].AllowHTTP = allow
		p.Update(&next)
		for _, host := range []string{"dev.example.com", "dev.example.com.evil.test"} {
			for _, existing := range []string{"", "Basic existing"} {
				req := httptest.NewRequest("GET", "http://"+net.JoinHostPort(host, port)+"/", nil)
				if existing != "" {
					req.Header.Set("Authorization", existing)
				}
				w := httptest.NewRecorder()
				p.ServeHTTP(w, req)
				want := existing
				if allow && host == "dev.example.com" {
					want = "Basic dXNlcjpzZWNyZXQ="
				}
				if w.Code != 200 || w.Body.String() != want {
					t.Fatalf("allow=%v host=%s: %d %q want %q", allow, host, w.Code, w.Body.String(), want)
				}
			}
		}
	}
}

func TestNonASCIIHostsGetNoCredentials(t *testing.T) {
	c := &config.Config{Listen: "127.0.0.1:18080", TrustedDomains: []string{"internal.test"}, Rules: []config.Rule{{HostPrefix: "dev.", Username: "user", Password: "secret", Enabled: true, AllowHTTP: true}}}
	p, err := New(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, host := range []string{"dev.İnternal.test:443", "dev.internal.tes\u212A:443", "[dev.İnternal.test]:443"} {
		req := httptest.NewRequest(http.MethodConnect, "http://127.0.0.1:18080/", nil)
		req.Host = host
		req.URL = &url.URL{Host: host}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("CONNECT %q: got %d, want 400", host, w.Code)
		}
	}
	// Plain HTTP: the request may be forwarded, but never with credentials.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "auth="+r.Header.Get("Authorization")) }))
	defer upstream.Close()
	p.transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	for host, want := range map[string]string{"dev.internal.test": "auth=Basic dXNlcjpzZWNyZXQ=", "dev.İnternal.test": "auth=", "dev.internal.tes\u212A": "auth="} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)
		req.URL.Host = host
		req.Host = host
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		if w.Body.String() != want {
			t.Errorf("GET http://%s: %d %q, want %q", host, w.Code, w.Body.String(), want)
		}
	}
}
