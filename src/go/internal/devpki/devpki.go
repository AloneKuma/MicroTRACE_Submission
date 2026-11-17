// Package devpki makes a development CA, a receiver certificate and one
// client certificate per node for the shipping link. For development and tests
// only; never for an evaluated run.
package devpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Files names the generated files in a directory.
type Files struct{ Dir string }

func (f Files) CA() string                  { return filepath.Join(f.Dir, "ca.crt") }
func (f Files) ReceiverCert() string        { return filepath.Join(f.Dir, "receiver.crt") }
func (f Files) ReceiverKey() string         { return filepath.Join(f.Dir, "receiver.key") }
func (f Files) NodeCert(node string) string { return filepath.Join(f.Dir, "node-cert-"+node+".crt") }
func (f Files) NodeKey(node string) string  { return filepath.Join(f.Dir, "node-cert-"+node+".key") }

// Generate writes ca.crt, receiver.{crt,key} (valid for hosts) and
// node-cert-<id>.{crt,key} for each node ID (common name = node ID).
func Generate(dir string, nodes, hosts []string, validity time.Duration) (Files, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Files{}, err
	}
	until := time.Now().Add(validity)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Files{}, err
	}
	caTmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "microtrace-dev-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: until, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return Files{}, err
	}
	ca, _ := x509.ParseCertificate(der)
	if err := write(dir, "ca", ca, nil); err != nil {
		return Files{}, err
	}
	srv := &x509.Certificate{Subject: pkix.Name{CommonName: "ingest-receiver"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			srv.IPAddresses = append(srv.IPAddresses, ip)
		} else if h != "" {
			srv.DNSNames = append(srv.DNSNames, h)
		}
	}
	if err := issue(dir, "receiver", srv, ca, caKey, until); err != nil {
		return Files{}, err
	}
	for _, n := range nodes {
		if n == "" {
			continue
		}
		c := &x509.Certificate{Subject: pkix.Name{CommonName: n}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if err := issue(dir, "node-cert-"+n, c, ca, caKey, until); err != nil {
			return Files{}, err
		}
	}
	return Files{Dir: dir}, nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func issue(dir, name string, tmpl, ca *x509.Certificate, caKey *ecdsa.PrivateKey, until time.Time) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl.SerialNumber, tmpl.NotBefore, tmpl.NotAfter = serial(), time.Now().Add(-time.Hour), until
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	cert, _ := x509.ParseCertificate(der)
	return write(dir, name, cert, key)
}

func write(dir, name string, cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(filepath.Join(dir, name+".crt"), certPEM, 0o644); err != nil {
		return err
	}
	if key == nil {
		return nil
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".key"),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}
