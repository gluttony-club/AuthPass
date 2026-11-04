// Package proxy implements HTTP/1.1 forwarding and target-only TLS interception.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/gluttony-club/AuthPass/internal/ca"
	"github.com/gluttony-club/AuthPass/internal/config"
	"github.com/gluttony-club/AuthPass/internal/instance"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Server struct {
	Config    *config.Config
	current   atomic.Pointer[config.Config]
	Local     http.Handler
	CA        *ca.Authority
	transport *http.Transport
	dial      func(context.Context, string, string) (net.Conn, error)
	mu        sync.Mutex
	conns     map[net.Conn]bool
	closed    bool
}

func New(c *config.Config, a *ca.Authority) (*Server, error) {
	h, _, e := net.SplitHostPort(c.Listen)
	if e != nil || (h != "127.0.0.1" && h != "localhost") {
		return nil, fmt.Errorf("proxy must listen on loopback host:port")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.InsecureSkipVerifyUpstream} // Explicit opt-in for internal development servers only.
	if c.UpstreamCAFile != "" {
		b, e := os.ReadFile(c.UpstreamCAFile)
		if e != nil {
			return nil, e
		}
		pool, e := x509.SystemCertPool()
		if e != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("upstream_ca_file has no certificates")
		}
		tc.RootCAs = pool
	}
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	s := &Server{Config: c, CA: a, conns: make(map[net.Conn]bool)}
	s.current.Store(c)
	s.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		h, p, e := net.SplitHostPort(addr)
		if e != nil {
			return nil, e
		}
		if v := c.HostOverrides[config.Host(h)]; v != "" {
			addr = net.JoinHostPort(v, p)
		}
		return d.DialContext(ctx, network, addr)
	}
	s.transport = &http.Transport{DialContext: s.dial, TLSClientConfig: tc, ForceAttemptHTTP2: false, MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	return s, nil
}
func (s *Server) Close() {
	s.transport.CloseIdleConnections()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for c := range s.conns {
		_ = c.Close()
	}
}
func strip(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, k := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(k))
		}
	}
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "proxy-") {
			h.Del(k)
		}
	}
	for _, k := range []string{"Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(k)
	}
}
func (s *Server) forward(r *http.Request, scheme, authority string) (*http.Response, error) {
	q := r.Clone(r.Context())
	q.RequestURI = ""
	q.URL.Scheme = scheme
	q.URL.Host = authority
	q.Host = authority
	strip(q.Header)
	if t := s.current.Load().Target(authority); t != nil && (scheme == "https" || t.AllowHTTP) {
		q.SetBasicAuth(t.Username, t.Password)
	}
	resp, e := s.transport.RoundTrip(q)
	if e == nil {
		strip(resp.Header)
	}
	return resp, e
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.IsAbs() && (r.URL.Path == "/settings" || strings.HasPrefix(r.URL.Path, "/api/")) {
		_, port, _ := net.SplitHostPort(s.Config.Listen)
		if r.URL.Host == "127.0.0.1:"+port || r.URL.Host == "localhost:"+port {
			http.Error(w, "settings require direct requests", http.StatusForbidden)
			return
		}
	}

	if r.Method == http.MethodConnect {
		s.connect(w, r)
		return
	}
	if !r.URL.IsAbs() {
		if s.Local != nil && (r.URL.Path == "/settings" || strings.HasPrefix(r.URL.Path, "/api/")) {
			s.Local.ServeHTTP(w, r)
			return
		}
		switch r.URL.Path {
		case s.Config.PACPath:
			w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
			w.Header().Set("Cache-Control", "no-cache")
			_, _ = io.WriteString(w, PAC(s.current.Load()))
		case instance.PingPath:
			w.Write([]byte(instance.Identity))
			return
		case "/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"running": true})
		default:
			http.NotFound(w, r)
		}
		return
	}
	if r.URL.Scheme != "http" {
		http.Error(w, "use CONNECT for HTTPS", 400)
		return
	}
	resp, e := s.forward(r, "http", r.URL.Host)
	if e != nil {
		http.Error(w, e.Error(), 502)
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	host, _, e := net.SplitHostPort(r.Host)
	if e != nil {
		http.Error(w, "CONNECT requires host:port", 400)
		return
	}
	var upstream net.Conn
	if s.current.Load().Target(host) == nil {
		upstream, e = s.dial(r.Context(), "tcp", r.Host)
		if e != nil {
			http.Error(w, e.Error(), 502)
			return
		}
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		if upstream != nil {
			upstream.Close()
		}
		http.Error(w, "hijacking unavailable", 500)
		return
	}
	conn, rw, e := hj.Hijack()
	if e != nil {
		if upstream != nil {
			upstream.Close()
		}
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.Close()
		if upstream != nil {
			upstream.Close()
		}
		return
	}
	s.conns[conn] = true
	s.mu.Unlock()
	defer func() { conn.Close(); s.mu.Lock(); delete(s.conns, conn); s.mu.Unlock() }()
	if _, e = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil {
		return
	}
	if e = rw.Flush(); e != nil {
		return
	}
	if upstream != nil {
		defer upstream.Close()
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(upstream, rw)
			if t, ok := upstream.(*net.TCPConn); ok {
				_ = t.CloseWrite()
			}
			close(done)
		}()
		_, _ = io.Copy(conn, upstream)
		conn.Close()
		upstream.Close()
		<-done
		return
	}
	cert, e := s.CA.Certificate(config.Host(host))
	if e != nil {
		return
	}
	// Preserve bytes already buffered by net/http before hijacking.
	t := tls.Server(&bufferedConn{Conn: conn, r: rw.Reader}, &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if e = t.Handshake(); e != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	defer t.Close()
	br := bufio.NewReader(t)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		req, e := http.ReadRequest(br)
		if e != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
		// Pin every inner request to the CONNECT authority, preventing cross-host credential leakage.
		if !strings.EqualFold(req.Host, r.Host) && !strings.EqualFold(req.Host, host) {
			req.Body.Close()
			return
		}
		resp, e := s.forward(req, "https", r.Host)
		req.Body.Close()
		if e != nil {
			_, _ = io.WriteString(t, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			return
		}
		resp.Close = req.Close
		e = resp.Write(t)
		resp.Body.Close()
		if e != nil || req.Close {
			return
		}
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func PAC(c *config.Config) string {
	var b strings.Builder
	b.WriteString("function FindProxyForURL(url, host) {\n  host = host.toLowerCase().replace(/\\.$/, \"\");\n")
	quote := func(v string) string { x, _ := json.Marshal(v); return string(x) }
	for i, r := range c.Rules {
		if !r.Enabled || r.Username == "" {
			continue
		}
		condition := "shExpMatch(host, " + quote(r.HostPrefix+"*") + ")"
		// An earlier unconfigured rule still wins overlapping prefixes.
		for _, previous := range c.Rules[:i] {
			if previous.Enabled && previous.Username == "" && (strings.HasPrefix(r.HostPrefix, previous.HostPrefix) || strings.HasPrefix(previous.HostPrefix, r.HostPrefix)) {
				condition += " && !shExpMatch(host, " + quote(previous.HostPrefix+"*") + ")"
			}
		}
		for _, d := range c.TrustedDomains {
			domainCondition := "(host == " + quote(d) + " || dnsDomainIs(host, " + quote("."+d) + "))"
			fmt.Fprintf(&b, "  if (%s && %s) return %s;\n", condition, domainCondition, quote("PROXY "+c.Listen))
		}
	}
	b.WriteString("  return \"DIRECT\";\n}\n")
	return b.String()
}

// Update publishes an immutable configuration snapshot.
func (s *Server) Update(c *config.Config) { s.current.Store(c) }
