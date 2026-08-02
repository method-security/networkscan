package pkinit

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"
)

// ParsePFX extracts the private key and leaf certificate from a PFX/PKCS12 file.
func ParsePFX(pfxData []byte, password string) (privateKey *rsa.PrivateKey, cert *x509.Certificate, err error) {
	key, leafCert, err := pkcs12.Decode(pfxData, password)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode PFX file: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("PFX private key is not RSA (PKINIT requires RSA)")
	}

	return rsaKey, leafCert, nil
}
