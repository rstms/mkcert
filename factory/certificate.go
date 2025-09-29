package factory

import (
	"crypto/x509"
	"encoding/pem"
	"os"
)

func ReadCertificate(certFile string) (*x509.Certificate, error) {
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		return nil, Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, Fatalf("failed decoding PEM block: %s", certFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, Fatal(err)
	}
	return cert, nil
}
