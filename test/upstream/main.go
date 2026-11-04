package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func main() {
	dir := flag.String("dir", ".", "output directory")
	flag.Parse()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test upstream"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), DNSNames: []string{"dev.foo.test", "feature.bar.test", "other.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, _ := x509.CreateCertificate(rand.Reader, c, c, &k.PublicKey, k)
	key, _ := x509.MarshalECPrivateKey(k)
	cp := filepath.Join(*dir, "upstream.crt")
	kp := filepath.Join(*dir, "upstream.key")
	must(os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	must(os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key}), 0600))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || !((u == "test-user" && p == "test-password") || (u == "feature-user" && p == "feature-password")) {
			w.WriteHeader(401)
		}
		fmt.Fprintf(w, "auth_received=%v user=%s\n", ok, u)
	})
	l, e := net.Listen("tcp", "127.0.0.1:0")
	must(e)
	s, e := net.Listen("tcp", "127.0.0.1:0")
	must(e)
	go func() { must(http.Serve(l, h)) }()
	must(os.WriteFile(filepath.Join(*dir, "ports"), []byte(fmt.Sprintf("%d %d", l.Addr().(*net.TCPAddr).Port, s.Addr().(*net.TCPAddr).Port)), 0600))
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	must(srv.ServeTLS(s, cp, kp))
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}
