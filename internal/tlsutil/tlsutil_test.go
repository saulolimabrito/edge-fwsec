package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mkPair(t *testing.T, key any, pub any, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "fw.example.test"},
		DNSNames: []string{"fw.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
}

func TestSelfSignedThenCustom(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, []string{"edge-fw", "10.99.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	in := s.Info()
	if in.Custom || len(in.IPAddresses) != 1 || in.IPAddresses[0] != "10.99.0.1" || in.DNSNames[0] != "edge-fw" {
		t.Fatalf("%+v", in)
	}
	fi, _ := os.Stat(filepath.Join(dir, "self.key"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatal("key permissions")
	}
	// reopening keeps the same certificate
	s2, _ := Open(dir, nil)
	if s2.Info().SHA256 != in.SHA256 {
		t.Fatal("self-signed certificate regenerated on restart")
	}

	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, kp := mkPair(t, k, &k.PublicKey, time.Now().Add(24*time.Hour))
	if err := s.SetCustom(c, kp); err != nil {
		t.Fatal(err)
	}
	if !s.Info().Custom || s.Info().DNSNames[0] != "fw.example.test" {
		t.Fatal("custom not active")
	}
	got, _ := s.Config().GetCertificate(nil)
	if got == nil {
		t.Fatal("no certificate served")
	}
	s3, _ := Open(dir, nil)
	if !s3.Info().Custom {
		t.Fatal("custom certificate not preferred after restart")
	}
	if err := s.RemoveCustom(); err != nil || s.Info().Custom || s.Info().SHA256 != in.SHA256 {
		t.Fatal("remove custom")
	}
}

func TestRejectsBadCustom(t *testing.T) {
	s, _ := Open(t.TempDir(), []string{"x"})
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c1, _ := mkPair(t, k1, &k1.PublicKey, time.Now().Add(time.Hour))
	_, kp2 := mkPair(t, k2, &k2.PublicKey, time.Now().Add(time.Hour))
	if s.SetCustom(c1, kp2) == nil {
		t.Error("mismatched key accepted")
	}
	ce, ke := mkPair(t, k1, &k1.PublicKey, time.Now().Add(-time.Minute))
	if s.SetCustom(ce, ke) == nil {
		t.Error("expired certificate accepted")
	}
	r, _ := rsa.GenerateKey(rand.Reader, 1024)
	cr, kr := mkPair(t, r, &r.PublicKey, time.Now().Add(time.Hour))
	if s.SetCustom(cr, kr) == nil {
		t.Error("weak RSA accepted")
	}
	if s.SetCustom([]byte("junk"), []byte("junk")) == nil {
		t.Error("junk accepted")
	}
	if s.Info().Custom {
		t.Error("a rejected upload changed the active certificate")
	}
}
