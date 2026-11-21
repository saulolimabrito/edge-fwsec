// Package tlsutil manages the console certificate: a self-signed ECDSA
// certificate generated at first start, replaceable by an administrator
// supplied certificate without restarting the service.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/saulolimabrito/edge-fwsec/internal/fsutil"
)

// Store keeps the active key pair under dir (custom.* wins over self.*).
type Store struct {
	dir string
	mu  sync.RWMutex
	cur *tls.Certificate
	now func() time.Time
}

// Open loads the custom pair if present, else the self-signed one,
// generating it for hosts (DNS names or IPs) when missing.
func Open(dir string, hosts []string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, now: time.Now}
	if c, err := tls.LoadX509KeyPair(s.path("custom.crt"), s.path("custom.key")); err == nil {
		s.cur = &c
		return s, nil
	}
	c, err := tls.LoadX509KeyPair(s.path("self.crt"), s.path("self.key"))
	if err != nil {
		if err := s.generate(hosts); err != nil {
			return nil, err
		}
		if c, err = tls.LoadX509KeyPair(s.path("self.crt"), s.path("self.key")); err != nil {
			return nil, err
		}
	}
	s.cur = &c
	return s, nil
}

func (s *Store) path(n string) string { return filepath.Join(s.dir, n) }

func (s *Store) generate(hosts []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	now := s.now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Edge FWSec console", Organization: []string{"Edge FWSec (self-signed)"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if h != "" {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := fsutil.WriteAtomic(s.path("self.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return fsutil.WriteAtomic(s.path("self.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// Config returns a server TLS config that always serves the current pair.
func (s *Store) Config() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.mu.RLock()
			defer s.mu.RUnlock()
			return s.cur, nil
		},
	}
}

// Info describes the active certificate for the UI.
type Info struct {
	Custom      bool      `json:"custom"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	DNSNames    []string  `json:"dns_names"`
	IPAddresses []string  `json:"ip_addresses"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	SHA256      string    `json:"sha256"`
}

// Info returns details of the active certificate.
func (s *Store) Info() Info {
	s.mu.RLock()
	defer s.mu.RUnlock()
	leaf, _ := x509.ParseCertificate(s.cur.Certificate[0])
	in := Info{Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(), DNSNames: leaf.DNSNames,
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}
	for _, ip := range leaf.IPAddresses {
		in.IPAddresses = append(in.IPAddresses, ip.String())
	}
	sum := sha256.Sum256(s.cur.Certificate[0])
	in.SHA256 = hex.EncodeToString(sum[:])
	_, err := os.Stat(s.path("custom.crt"))
	in.Custom = err == nil
	return in
}

// SetCustom validates and installs an administrator certificate chain and
// key (PEM). The key must match, be ECDSA P-256/P-384 or RSA >= 2048, and
// the leaf must be valid now and for server authentication.
func (s *Store) SetCustom(certPEM, keyPEM []byte) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("certificate and key do not form a valid pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	now := s.now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return errors.New("certificate is not valid at the current time")
	}
	if len(leaf.ExtKeyUsage) > 0 {
		ok := false
		for _, u := range leaf.ExtKeyUsage {
			ok = ok || u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny
		}
		if !ok {
			return errors.New("certificate is not valid for server authentication")
		}
	}
	switch k := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if n := k.Curve.Params().Name; n != "P-256" && n != "P-384" {
			return fmt.Errorf("unsupported ECDSA curve %s", n)
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return errors.New("RSA keys must have at least 2048 bits")
		}
	default:
		return errors.New("only ECDSA and RSA keys are supported")
	}
	if err := fsutil.WriteAtomic(s.path("custom.key"), keyPEM, 0o600); err != nil {
		return err
	}
	if err := fsutil.WriteAtomic(s.path("custom.crt"), certPEM, 0o644); err != nil {
		return err
	}
	s.mu.Lock()
	s.cur = &pair
	s.mu.Unlock()
	return nil
}

// RemoveCustom returns to the self-signed certificate.
func (s *Store) RemoveCustom() error {
	c, err := tls.LoadX509KeyPair(s.path("self.crt"), s.path("self.key"))
	if err != nil {
		return err
	}
	os.Remove(s.path("custom.crt"))
	os.Remove(s.path("custom.key"))
	s.mu.Lock()
	s.cur = &c
	s.mu.Unlock()
	return nil
}
