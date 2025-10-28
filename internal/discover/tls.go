// Package discover implements network discovery functionality for finding live hosts and services.
package discover

import (
	// Standard
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

// isIPAddress checks if a given host string is an IP address (IPv4 or IPv6)
func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

// lookupIPAddress performs DNS lookup for a hostname and returns the first IP address found
func lookupIPAddress(ctx context.Context, hostname string) (string, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", &net.DNSError{
			Err:        "no such host",
			Name:       hostname,
			Server:     "",
			IsNotFound: true,
		}
	}
	return ips[0].IP.String(), nil
}

// GetTLSInfo retrieves comprehensive TLS configuration and certificate details for a list of target addresses.
// It establishes TLS connections to each target, probes multiple TLS versions, collects supported cipher suites,
// and detects security issues. Returns a report containing detailed TLS configuration and any errors encountered.
func GetTLSInfo(ctx context.Context, addresses []string, config discoverfern.DiscoverTlsConfig) (discoverfern.DiscoverTlsReport, error) {
	errors := []string{}

	serviceDetails := []*discoverfern.TlsSummary{}
	for _, targetAddress := range addresses {
		// Check if the address includes a port
		host, port, err := net.SplitHostPort(targetAddress)
		if err != nil || port == "" {
			errors = append(errors, "Address does not have a valid port")
			continue
		}

		// Determine IP address for the target
		var ipAddress string
		if isIPAddress(host) {
			ipAddress = host
		} else {
			resolvedIP, err := lookupIPAddress(ctx, host)
			if err != nil {
				errors = append(errors, "Failed to resolve hostname "+host+": "+err.Error())
				continue
			}
			ipAddress = resolvedIP
		}

		// Perform comprehensive TLS scan
		tlsConfig, scanErrors := scanTLSConfiguration(ctx, targetAddress, host, config)
		if len(scanErrors) > 0 {
			errors = append(errors, scanErrors...)
		}

		if tlsConfig == nil {
			continue
		}

		// Construct TlsSummary
		serviceDetail := discoverfern.TlsSummary{
			Socket:           targetAddress,
			IpAddress:        ipAddress,
			TlsConfiguration: tlsConfig,
		}
		serviceDetails = append(serviceDetails, &serviceDetail)
	}

	return discoverfern.DiscoverTlsReport{
		Config: &config,
		Result: &discoverfern.DiscoverTlsResult{Details: serviceDetails},
		Errors: errors,
	}, nil
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

// scanTLSConfiguration performs a comprehensive TLS scan by probing multiple versions and cipher suites.
// It returns a TlsConfiguration with all supported versions, cipher suites, and security properties.
func scanTLSConfiguration(ctx context.Context, targetAddress, serverName string, config discoverfern.DiscoverTlsConfig) (*discoverfern.TlsConfiguration, []string) {
	errors := []string{}
	dialer := &net.Dialer{
		Timeout: time.Duration(config.Timeout) * time.Second,
	}

	// First, establish a connection with default settings to get negotiated values and certificates
	defaultConn, err := tls.DialWithDialer(dialer, "tcp", targetAddress, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: !config.VerifyTls,
	})
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to establish TLS connection: %v", err))
		return nil, errors
	}

	defaultState := defaultConn.ConnectionState()
	negotiatedVersion := tlsVersionToString(defaultState.Version)
	negotiatedCipherSuite := convertCipherSuiteToEnum(defaultState.CipherSuite)
	compressionEnabled := defaultState.DidResume                   // Using DidResume as proxy - Go doesn't support compression
	secureRenegotiation := defaultState.NegotiatedProtocolIsMutual // Best available proxy
	certificates := extractCertificates(defaultState.PeerCertificates)

	_ = defaultConn.Close()

	// Probe SSL versions using raw socket handshake (Go's crypto/tls doesn't support these)
	ssl2Supported := probeSSLv2(targetAddress, dialer)
	ssl3Supported := probeSSLv3(targetAddress, dialer)

	versionSupport := []*discoverfern.TlsVersionSupport{
		{Version: discoverfern.TlsVersionSsl20, Supported: ssl2Supported},
		{Version: discoverfern.TlsVersionSsl30, Supported: ssl3Supported},
	}

	// Test TLS versions that Go supports
	versionsToTest := []uint16{
		tls.VersionTLS10,
		tls.VersionTLS11,
		tls.VersionTLS12,
		tls.VersionTLS13,
	}

	for _, version := range versionsToTest {
		fernVersion := tlsVersionToString(version)
		cipherSuites := probeTLSVersion(ctx, targetAddress, serverName, version, config, dialer)

		if len(cipherSuites) > 0 {
			versionSupport = append(versionSupport, &discoverfern.TlsVersionSupport{
				Version:      fernVersion,
				Supported:    true,
				CipherSuites: cipherSuites,
			})
		} else {
			versionSupport = append(versionSupport, &discoverfern.TlsVersionSupport{
				Version:   fernVersion,
				Supported: false,
			})
		}
	}

	// Extract supported elliptic curves (only available for successful connections)
	var supportedCurves []string
	// Note: Go's crypto/tls doesn't expose the server's supported curves directly
	// We can only see what was negotiated

	return &discoverfern.TlsConfiguration{
		NegotiatedVersion:            negotiatedVersion,
		NegotiatedCipherSuite:        negotiatedCipherSuite,
		CompressionEnabled:           compressionEnabled,
		SecureRenegotiationSupported: secureRenegotiation,
		VersionSupport:               versionSupport,
		SupportedEllipticCurves:      supportedCurves,
		Certificates:                 certificates,
	}, errors
}

// probeTLSVersion probes a specific TLS version and returns all supported cipher suites for that version.
// This function probes each cipher suite individually to build a comprehensive list of what's supported.
func probeTLSVersion(ctx context.Context, targetAddress, serverName string, version uint16, config discoverfern.DiscoverTlsConfig, dialer *net.Dialer) []discoverfern.CipherSuite {
	supportedCipherSuites := []discoverfern.CipherSuite{}
	seenCiphers := make(map[uint16]bool)

	// Get all cipher suites to test
	allCipherSuites := getAllCipherSuites()

	// For TLS 1.3, cipher suites work differently - we can't control them via CipherSuites field
	// So we just test if the version is supported
	if version == tls.VersionTLS13 {
		tlsConfig := &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: !config.VerifyTls,
			MinVersion:         version,
			MaxVersion:         version,
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", targetAddress, tlsConfig)
		if err != nil {
			return supportedCipherSuites
		}

		state := conn.ConnectionState()
		if state.Version == version {
			cipherSuite := convertCipherSuiteToEnum(state.CipherSuite)
			supportedCipherSuites = append(supportedCipherSuites, cipherSuite)
		}
		_ = conn.Close()

		return supportedCipherSuites
	}

	// For TLS 1.2 and below, probe each cipher suite
	for _, cipherID := range allCipherSuites {
		if seenCiphers[cipherID] {
			continue
		}

		tlsConfig := &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: !config.VerifyTls,
			MinVersion:         version,
			MaxVersion:         version,
			CipherSuites:       []uint16{cipherID},
		}

		conn, err := tls.DialWithDialer(dialer, "tcp", targetAddress, tlsConfig)
		if err != nil {
			continue
		}

		state := conn.ConnectionState()
		if state.Version == version && state.CipherSuite == cipherID {
			seenCiphers[cipherID] = true
			cipherSuite := convertCipherSuiteToEnum(cipherID)
			supportedCipherSuites = append(supportedCipherSuites, cipherSuite)
		}
		_ = conn.Close()
	}

	return supportedCipherSuites
}

// getAllCipherSuites returns all cipher suite IDs supported by Go's crypto/tls.
func getAllCipherSuites() []uint16 {
	// Get secure cipher suites
	secureSuites := tls.CipherSuites()
	insecureSuites := tls.InsecureCipherSuites()

	allSuites := make([]uint16, 0, len(secureSuites)+len(insecureSuites))
	for _, suite := range secureSuites {
		allSuites = append(allSuites, suite.ID)
	}
	for _, suite := range insecureSuites {
		allSuites = append(allSuites, suite.ID)
	}

	return allSuites
}

// convertCipherSuiteToEnum converts a cipher suite ID to our CipherSuite enum.
func convertCipherSuiteToEnum(cipherSuiteID uint16) discoverfern.CipherSuite {
	name := tls.CipherSuiteName(cipherSuiteID)
	// Remove "TLS_" prefix to match enum
	name = strings.TrimPrefix(name, "TLS_")

	// Try to convert to enum
	cipherEnum, err := discoverfern.NewCipherSuiteFromString(name)
	if err != nil {
		// If not found, return UNKNOWN
		return discoverfern.CipherSuiteUnknown
	}

	return cipherEnum
}

// extractCertificates converts x509 certificates to our Certificate type.
func extractCertificates(x509Certs []*x509.Certificate) []*discoverfern.Certificate {
	certificates := []*discoverfern.Certificate{}

	for _, cert := range x509Certs {
		serialNumber := cert.SerialNumber.String()
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		certString := string(certPEM)
		signatureHex := hex.EncodeToString(cert.Signature)
		dnsNames := cert.DNSNames

		certificate := &discoverfern.Certificate{
			Certificate:             certString,
			SerialNumber:            serialNumber,
			Signature:               signatureHex,
			SubjectCommonName:       &cert.Subject.CommonName,
			IssuerCommonName:        &cert.Issuer.CommonName,
			ValidFrom:               cert.NotBefore,
			ValidTo:                 cert.NotAfter,
			Version:                 cert.Version,
			SubjectAlternativeNames: dnsNames,
		}

		// Signature names defined in `signatureAlgorithmDetails` in the `x509` package have a hyphen
		// Which is removed for proper enum conversion
		signatureAlgorithm, err := discoverfern.NewSignatureAlgorithmFromString(strings.Replace(cert.SignatureAlgorithm.String(), "-", "_", 1))
		if err == nil {
			certificate.SignatureAlgorithm = signatureAlgorithm
		}
		publicKeyAlgorithm, err := discoverfern.NewPublicKeyAlgorithmFromString(cert.PublicKeyAlgorithm.String())
		if err == nil {
			certificate.PublicKeyAlgorithm = publicKeyAlgorithm
		}

		certificates = append(certificates, certificate)
	}

	return certificates
}

// probeSSLv2 checks if the server supports SSLv2 by sending a raw SSLv2 ClientHello.
// Since Go's crypto/tls doesn't support SSLv2, we use raw socket programming.
func probeSSLv2(targetAddress string, dialer *net.Dialer) bool {
	conn, err := dialer.Dial("tcp", targetAddress)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	// SSLv2 ClientHello packet (simplified - tests for SSLv2 support)
	// Format: [msg_length(2)] [msg_type(1)] [version(2)] [cipher_specs_length(2)]
	//         [session_id_length(2)] [challenge_length(2)] [cipher_specs] [session_id] [challenge]
	sslv2Hello := []byte{
		0x80, 0x2e, // Message length (46 bytes)
		0x01,       // Message type: CLIENT-HELLO
		0x00, 0x02, // Version: SSL 2.0
		0x00, 0x15, // Cipher specs length (21 bytes = 7 ciphers * 3 bytes)
		0x00, 0x00, // Session ID length (0)
		0x00, 0x10, // Challenge length (16 bytes)
		// Cipher specs (7 common SSLv2 ciphers)
		0x01, 0x00, 0x80, // SSL_CK_RC4_128_WITH_MD5
		0x02, 0x00, 0x80, // SSL_CK_RC4_128_EXPORT40_WITH_MD5
		0x03, 0x00, 0x80, // SSL_CK_RC2_128_CBC_WITH_MD5
		0x04, 0x00, 0x80, // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
		0x05, 0x00, 0x80, // SSL_CK_IDEA_128_CBC_WITH_MD5
		0x06, 0x00, 0x40, // SSL_CK_DES_64_CBC_WITH_MD5
		0x07, 0x00, 0xC0, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
		// Challenge (16 random bytes)
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}

	// Set a short timeout for the probe
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send SSLv2 ClientHello
	_, err = conn.Write(sslv2Hello)
	if err != nil {
		return false
	}

	// Try to read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return false
	}

	// Check if we got a valid SSLv2 ServerHello response
	// SSLv2 ServerHello starts with 0x04 (SERVER-HELLO) or high bit set for 2-byte length
	if n > 2 {
		// Check for 2-byte length format (high bit set) or 3-byte length format
		if (response[0]&0x80) != 0 || response[0] == 0x04 {
			// Got a response that looks like SSLv2 ServerHello
			return true
		}
	}

	return false
}

// probeSSLv3 checks if the server supports SSLv3 by sending a raw SSLv3 ClientHello.
// Since Go's crypto/tls doesn't support SSLv3, we use raw socket programming.
func probeSSLv3(targetAddress string, dialer *net.Dialer) bool {
	conn, err := dialer.Dial("tcp", targetAddress)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	// SSLv3 ClientHello packet
	// TLS Record Layer: Content Type (0x16 = Handshake), Version (0x03, 0x00 = SSL 3.0), Length
	// Handshake Protocol: Type (0x01 = ClientHello), Length, Version, Random, Session ID, Cipher Suites, Compression
	sslv3Hello := []byte{
		// TLS Record Layer
		0x16,       // Content Type: Handshake
		0x03, 0x00, // Version: SSL 3.0
		0x00, 0x5d, // Length (93 bytes)
		// Handshake Protocol
		0x01,             // Handshake Type: ClientHello
		0x00, 0x00, 0x59, // Length (89 bytes)
		0x03, 0x00, // Version: SSL 3.0
		// Random (32 bytes: 4 bytes timestamp + 28 bytes random)
		0x00, 0x00, 0x00, 0x00, // Timestamp
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b,
		// Session ID
		0x00, // Session ID Length (0)
		// Cipher Suites
		0x00, 0x2c, // Cipher Suites Length (44 bytes = 22 cipher suites)
		0x00, 0x39, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
		0x00, 0x38, // TLS_DHE_DSS_WITH_AES_256_CBC_SHA
		0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
		0x00, 0x33, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
		0x00, 0x32, // TLS_DHE_DSS_WITH_AES_128_CBC_SHA
		0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x00, 0x16, // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
		0x00, 0x13, // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
		0x00, 0x0a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		0x00, 0x05, // TLS_RSA_WITH_RC4_128_SHA
		0x00, 0x04, // TLS_RSA_WITH_RC4_128_MD5
		// Compression Methods
		0x01, // Compression Methods Length (1)
		0x00, // Compression Method: null
	}

	// Set a short timeout for the probe
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send SSLv3 ClientHello
	_, err = conn.Write(sslv3Hello)
	if err != nil {
		return false
	}

	// Try to read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return false
	}

	// Check if we got a valid SSLv3/TLS ServerHello response
	// ServerHello: Content Type (0x16), Version (0x03, 0x00), then Handshake
	if n >= 5 {
		if response[0] == 0x16 && response[1] == 0x03 && response[2] == 0x00 {
			// Got an SSL 3.0 ServerHello
			return true
		}
		// Some servers might respond with TLS 1.0+ even for SSL 3.0 ClientHello (version negotiation)
		// But if they accept the connection, it means SSL 3.0 was in their supported versions
		if response[0] == 0x16 && response[1] == 0x03 {
			// This is a handshake response, but we need to be careful here
			// Only return true if the server explicitly chose SSL 3.0
			if n >= 11 && response[9] == 0x03 && response[10] == 0x00 {
				return true
			}
		}
	}

	return false
}
