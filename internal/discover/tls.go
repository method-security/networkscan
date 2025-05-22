// Package discover implements network discovery functionality for finding live hosts and services.
package discover

import (
	// Standard
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"net"
	"strings"
	"time"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

// GetTLSInfo retrieves TLS configuration and certificate details for a list of target addresses.
// It establishes TLS connections to each target and extracts information about the TLS version,
// cipher suite, and certificates. Returns a report containing the TLS details and any errors encountered.
func GetTLSInfo(ctx context.Context, addresses []string, config discoverfern.DiscoverTlsConfig) (discoverfern.DiscoverTlsReport, error) {
	resources := discoverfern.DiscoverTlsReport{Config: &config}
	errors := []string{}

	serviceDetails := []*discoverfern.TlsSummary{}
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
			InsecureSkipVerify: !config.VerifyTls,
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
		serviceDetail := discoverfern.TlsSummary{
			Address:    targetAddress,
			TlsDetails: tlsInfo,
		}
		serviceDetails = append(serviceDetails, &serviceDetail)
	}

	resources.Details = serviceDetails
	resources.Errors = errors

	return resources, nil
}

// tlsVersionToString converts a TLS version number to our internal enum type.
// Maps standard TLS version constants to their corresponding enum values.
func tlsVersionToString(version uint16) discoverfern.TlsVersion {
	switch version {
	case tls.VersionTLS10:
		return discoverfern.TlsVersionTls10
	case tls.VersionTLS11:
		return discoverfern.TlsVersionTls11
	case tls.VersionTLS12:
		return discoverfern.TlsVersionTls12
	case tls.VersionTLS13:
		return discoverfern.TlsVersionTls13
	default:
		return discoverfern.TlsVersionUnknown
	}
}

// convertToTLSInfo extracts and formats TLS connection state information into our internal format.
// It processes the TLS version, cipher suite, and certificate chain, including detailed certificate information.
func convertToTLSInfo(state *tls.ConnectionState) *discoverfern.TlsDetails {
	tlsInfo := &discoverfern.TlsDetails{
		Certificates: []*discoverfern.Certificate{},
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
		certificate := &discoverfern.Certificate{
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
		signatureAlgorithm, err := discoverfern.NewSignatureAlgorithmFromString(strings.Replace(cert.SignatureAlgorithm.String(), "-", "_", 1))
		if err == nil {
			certificate.SignatureAlgorithm = &signatureAlgorithm
		}
		publicKeyAlgorithm, err := discoverfern.NewPublicKeyAlgorithmFromString(cert.PublicKeyAlgorithm.String())
		if err == nil {
			certificate.PublicKeyAlgorithm = &publicKeyAlgorithm
		}

		tlsInfo.Certificates = append(tlsInfo.Certificates, certificate)
	}

	return tlsInfo
}
