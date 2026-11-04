package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const Name = "BasicAuth Helper Local CA"

type Authority struct {
	CertPath string
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	mu       sync.Mutex
	cache    map[string]*tls.Certificate
}

func serial() *big.Int {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		panic(e)
	}
	return n
}
func Open(dir string) (*Authority, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	a := &Authority{CertPath: filepath.Join(dir, "ca.crt"), cache: make(map[string]*tls.Certificate)}
	kp := filepath.Join(dir, "ca.key")
	cb, ce := os.ReadFile(a.CertPath)
	kb, ke := os.ReadFile(kp)
	if os.IsNotExist(ce) && os.IsNotExist(ke) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, e
		}
		now := time.Now()
		t := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: Name}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		der, e := x509.CreateCertificate(rand.Reader, t, t, &key.PublicKey, key)
		if e != nil {
			return nil, e
		}
		kd, e := x509.MarshalECPrivateKey(key)
		if e != nil {
			return nil, e
		}
		cb = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		kb = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
		if e = os.WriteFile(kp, kb, 0600); e != nil {
			return nil, e
		}
		if e = os.WriteFile(a.CertPath, cb, 0600); e != nil {
			return nil, e
		}
	} else if ce != nil || ke != nil {
		return nil, fmt.Errorf("incomplete CA files: cert=%v key=%v", ce, ke)
	}
	pair, e := tls.X509KeyPair(cb, kb)
	if e != nil {
		return nil, e
	}
	a.cert, e = x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, e
	}
	var ok bool
	a.key, ok = pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key must be ECDSA")
	}
	if !a.cert.IsCA || time.Now().After(a.cert.NotAfter) {
		return nil, fmt.Errorf("invalid or expired root CA")
	}
	for _, p := range []string{kp, a.CertPath} {
		if e := os.Chmod(p, 0600); e != nil {
			return nil, e
		}
	}
	return a, nil
}
func (a *Authority) Certificate(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c := a.cache[host]; c != nil && time.Now().Add(time.Hour).Before(c.Leaf.NotAfter) {
		return c, nil
	}
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	now := time.Now()
	end := now.Add(396 * 24 * time.Hour)
	if end.After(a.cert.NotAfter) {
		end = a.cert.NotAfter
	}
	t := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: host}, NotBefore: now.Add(-time.Hour), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		t.IPAddresses = []net.IP{ip}
	} else {
		t.DNSNames = []string{host}
	}
	der, e := x509.CreateCertificate(rand.Reader, t, a.cert, &k.PublicKey, a.key)
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		return nil, e
	}
	c := &tls.Certificate{Certificate: [][]byte{der, a.cert.Raw}, PrivateKey: k, Leaf: leaf}
	a.cache[host] = c
	return c, nil
}
