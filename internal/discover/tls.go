package discover

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"net"
	"strings"
	"time"

	discoverFern "github.com/Method-Security/networkscan/generated/go/discover"
)

// GetTLSInfo retrieves TLS details for a given address
func GetTLSInfo(ctx context.Context, addresses []string, config discoverFern.DiscoverTlsConfig) (discoverFern.DiscoverTlsReport, error) {
	resources := discoverFern.DiscoverTlsReport{Config: &config}
	errors := []string{}

	serviceDetails := []*discoverFern.DiscoverTlsSummary{}
	for _, targetAddress := range addresses {
		// Define timeout for the TLS connection
		dialer := &net.Dialer{
			Timeout: time.Duration(config.Timeout) * time.Second,
		}

		// Check if the address includes a port
		_, port, err := net.SplitHostPort(targetAddress)
		if err != nil || port == "" {
			errors = append(errors, "Address does not have a valid port")
			continue
		}

		// Establish TLS connection
		conn, err := tls.DialWithDialer(dialer, "tcp", targetAddress, &tls.Config{
			InsecureSkipVerify: config.InsecureSkipVerify,
		})
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		// Get TLS connection state
		state := conn.ConnectionState()

		// Convert to TLSInfo struct
		tlsInfo := convertToTLSInfo(&state)

		// Close connection
		err = conn.Close()
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		// Construct AddressTlsReport
		serviceDetail := discoverFern.DiscoverTlsSummary{
			Address:    targetAddress,
			TlsDetails: tlsInfo,
		}
		serviceDetails = append(serviceDetails, &serviceDetail)
	}

	resources.Details = serviceDetails
	resources.Errors = errors

	return resources, nil
}

// Map TLS version to string
func tlsVersionToString(version uint16) discoverFern.TlsVersion {
	switch version {
	case tls.VersionTLS10:
		return discoverFern.TlsVersionTls10
	case tls.VersionTLS11:
		return discoverFern.TlsVersionTls11
	case tls.VersionTLS12:
		return discoverFern.TlsVersionTls12
	case tls.VersionTLS13:
		return discoverFern.TlsVersionTls13
	default:
		return discoverFern.TlsVersionUnknown
	}
}

// Convert TLS connection state to TLSInfo
func convertToTLSInfo(state *tls.ConnectionState) *discoverFern.DiscoverTlsDetails {
	tlsInfo := &discoverFern.DiscoverTlsDetails{
		Certificates: []*discoverFern.Certificate{},
	}

	if state.Version != 0 {
		version := tlsVersionToString(state.Version)
		tlsInfo.Version = &version
	}

	if state.CipherSuite != 0 {
		cipherSuite := tls.CipherSuiteName(state.CipherSuite)
		tlsInfo.CipherSuite = &cipherSuite
	}

	for _, cert := range state.PeerCertificates {
		serialNumber := cert.SerialNumber.String()
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		certString := string(certPEM)
		signatureHex := hex.EncodeToString(cert.Signature)
		certificate := &discoverFern.Certificate{
			SubjectCommonName: &cert.Subject.CommonName,
			IssuerCommonName:  &cert.Issuer.CommonName,
			ValidFrom:         &cert.NotBefore,
			ValidTo:           &cert.NotAfter,
			Version:           &cert.Version,
			SerialNumber:      &serialNumber,
			Certificate:       &certString,
			Signature:         &signatureHex,
		}

		// Signature names defined in `signatureAlgorithmDetails` in the `x509` package have a hyphen
		// Which is removed for proper enum conversion
		signatureAlgorithm, err := discoverFern.NewSignatureAlgorithmFromString(strings.Replace(cert.SignatureAlgorithm.String(), "-", "_", 1))
		if err == nil {
			certificate.SignatureAlgorithm = &signatureAlgorithm
		}
		publicKeyAlgorithm, err := discoverFern.NewPublicKeyAlgorithmFromString(cert.PublicKeyAlgorithm.String())
		if err == nil {
			certificate.PublicKeyAlgorithm = &publicKeyAlgorithm
		}

		tlsInfo.Certificates = append(tlsInfo.Certificates, certificate)
	}

	return tlsInfo
}
