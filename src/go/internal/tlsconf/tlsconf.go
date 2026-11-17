// Package tlsconf builds the TLS 1.3 settings of the shipping link: the
// receiver requires a client certificate from the shipping CA, and a node's
// identity is its certificate's common name.
package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
)

func pool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(pem) {
		return nil, errors.New("no certificates in " + caFile)
	}
	return p, nil
}

// Server is the receiver side: TLS 1.3 only, client certificate required and
// verified against caFile.
func Server(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cas, err := pool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cas,
	}, nil
}

// Client is the shipper side: TLS 1.3 only, presents the node certificate,
// verifies the receiver against caFile and serverName.
func Client(certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cas, err := pool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      cas,
		ServerName:   serverName,
	}, nil
}
