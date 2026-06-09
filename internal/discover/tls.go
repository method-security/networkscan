// Package discover implements network discovery functionality for finding live hosts and services.
package discover

import (
	// Standard
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	// External
	jarm "github.com/hdm/jarm-go"
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
func GetTLSInfo(ctx context.Context, config discoverfern.DiscoverTlsConfig) (discoverfern.DiscoverTlsReport, error) {
	errors := []string{}

	serviceDetails := []*discoverfern.TlsSummary{}
	for _, targetAddress := range config.Targets {
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

	// Establish a connection with InsecureSkipVerify to always collect TLS data.
	// We use MinVersion=TLS 1.0 so we can connect to legacy servers.
	// Verification errors are reported separately without blocking the scan.
	var negotiatedVersion discoverfern.TlsVersion
	var negotiatedCipherSuite discoverfern.CipherSuite
	var certificates []*discoverfern.Certificate

	defaultConn, err := tls.DialWithDialer(dialer, "tcp", targetAddress, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10, //nolint:gosec
	})
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to establish TLS connection: %v", err))
		return nil, errors
	}

	defaultState := defaultConn.ConnectionState()
	negotiatedVersion = tlsVersionToString(defaultState.Version)
	negotiatedCipherSuite = convertCipherSuiteToEnum(defaultState.CipherSuite)
	computeJA4X := config.Ja4X != nil && *config.Ja4X
	certificates = extractCertificates(defaultState.PeerCertificates, computeJA4X)
	_ = defaultConn.Close()

	compressionEnabled := probeCompression(targetAddress, serverName, dialer)
	secureRenegotiation := probeSecureRenegotiation(targetAddress, serverName, dialer)

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

	tlsTimeout := time.Duration(config.Timeout) * time.Second

	var ja4sFingerprint *string
	if config.Ja4S != nil && *config.Ja4S {
		v := computeJA4S(targetAddress, serverName, tlsTimeout)
		if v != "" {
			ja4sFingerprint = &v
		}
	}

	var jarmFingerprint *string
	if config.Jarm != nil && *config.Jarm {
		v := computeJARM(targetAddress, tlsTimeout)
		jarmFingerprint = &v
	}

	return &discoverfern.TlsConfiguration{
		NegotiatedVersion:            negotiatedVersion,
		NegotiatedCipherSuite:        negotiatedCipherSuite,
		CompressionEnabled:           compressionEnabled,
		SecureRenegotiationSupported: secureRenegotiation,
		VersionSupport:               versionSupport,
		SupportedEllipticCurves:      supportedCurves,
		Certificates:                 certificates,
		Ja4SFingerprint:              ja4sFingerprint,
		JarmFingerprint:              jarmFingerprint,
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
			InsecureSkipVerify: true,
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

	// For TLS 1.2 and below, probe each cipher suite.
	// Always use InsecureSkipVerify here since we're probing for cipher support, not validating certs.
	for _, cipherID := range allCipherSuites {
		if seenCiphers[cipherID] {
			continue
		}

		tlsConfig := &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			MinVersion:         version, //nolint:gosec
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
// When withJA4X is true, a JA4X fingerprint is computed for each certificate.
func extractCertificates(x509Certs []*x509.Certificate, withJA4X bool) []*discoverfern.Certificate {
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

		if withJA4X {
			fp := computeJA4XForCert(cert)
			certificate.Ja4XFingerprint = &fp
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

// probeCompression checks if the server supports TLS compression by sending a ClientHello
// that offers DEFLATE compression (method 1) alongside null compression (method 0).
// If the server selects a non-null compression method, compression is enabled.
func probeCompression(targetAddress, serverName string, dialer *net.Dialer) bool {
	conn, err := dialer.Dial("tcp", targetAddress)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	sniExtension := buildSNIExtension(serverName)

	// Build ClientHello offering DEFLATE + null compression (no SCSV — pure compression probe)
	clientHello := buildClientHello(0x03, 0x01, baseCipherSuites, sniExtension, []byte{0x01, 0x00}) // DEFLATE, null

	record := buildTLSRecord(0x16, 0x03, 0x01, clientHello)

	if _, err := conn.Write(record); err != nil {
		return false
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil || n < 44 {
		return false
	}

	// Parse TLS record: type(1) version(2) length(2) -> handshake
	if response[0] != 0x16 {
		return false
	}

	// Parse handshake header: type(1) length(3) -> ServerHello
	hsOffset := 5 // skip record header
	if hsOffset >= n || response[hsOffset] != 0x02 {
		return false
	}

	// ServerHello: version(2) random(32) session_id_len(1) session_id(...) cipher_suite(2) compression_method(1)
	shOffset := hsOffset + 4 // skip handshake header
	if shOffset+35 > n {
		return false
	}
	sessionIDLen := int(response[shOffset+34])
	compressionOffset := shOffset + 34 + 1 + sessionIDLen + 2 // +2 for cipher suite

	if compressionOffset >= n {
		return false
	}

	return response[compressionOffset] != 0x00
}

// probeSecureRenegotiation checks if the server supports RFC 5746 secure renegotiation
// by sending a ClientHello with the renegotiation_info extension (0xff01) and checking
// if the ServerHello includes the same extension in its response.
func probeSecureRenegotiation(targetAddress, serverName string, dialer *net.Dialer) bool {
	conn, err := dialer.Dial("tcp", targetAddress)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	sniExtension := buildSNIExtension(serverName)
	// renegotiation_info extension (0xff01) with empty renegotiated_connection
	renegExt := []byte{0xff, 0x01, 0x00, 0x01, 0x00}

	var extensions []byte
	extensions = append(extensions, sniExtension...)
	extensions = append(extensions, renegExt...)

	// Use base ciphers without SCSV — rely solely on the renegotiation_info
	// extension to test server support, avoiding conflated signals.
	clientHello := buildClientHello(0x03, 0x01, baseCipherSuites, extensions, []byte{0x00}) // null compression only

	record := buildTLSRecord(0x16, 0x03, 0x01, clientHello)

	if _, err := conn.Write(record); err != nil {
		return false
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil || n < 44 {
		return false
	}

	if response[0] != 0x16 {
		return false
	}

	// Parse through the ServerHello to find extensions
	hsOffset := 5
	if hsOffset >= n || response[hsOffset] != 0x02 {
		return false
	}

	hsLen := int(response[hsOffset+1])<<16 | int(response[hsOffset+2])<<8 | int(response[hsOffset+3])
	shOffset := hsOffset + 4
	shEnd := shOffset + hsLen

	if shEnd > n {
		shEnd = n
	}

	// Skip version(2) + random(32) = 34
	if shOffset+35 > shEnd {
		return false
	}
	sessionIDLen := int(response[shOffset+34])
	// Skip session_id + cipher_suite(2) + compression(1)
	extListOffset := shOffset + 34 + 1 + sessionIDLen + 2 + 1

	if extListOffset+2 > shEnd {
		return false
	}

	extListLen := int(response[extListOffset])<<8 | int(response[extListOffset+1])
	extOffset := extListOffset + 2
	extEnd := extOffset + extListLen

	if extEnd > shEnd {
		extEnd = shEnd
	}

	// Walk extensions looking for renegotiation_info (0xff01)
	for extOffset+4 <= extEnd {
		extType := uint16(response[extOffset])<<8 | uint16(response[extOffset+1])
		extLen := int(response[extOffset+2])<<8 | int(response[extOffset+3])

		if extType == 0xff01 {
			return true
		}

		extOffset += 4 + extLen
	}

	return false
}

// buildSNIExtension builds a TLS SNI (Server Name Indication) extension for the given hostname.
func buildSNIExtension(serverName string) []byte {
	if serverName == "" || net.ParseIP(serverName) != nil {
		return nil
	}
	nameBytes := []byte(serverName)
	nameLen := len(nameBytes)

	ext := []byte{
		0x00, 0x00, // Extension type: server_name
		byte((nameLen + 5) >> 8), byte((nameLen + 5) & 0xff), // Extension length
		byte((nameLen + 3) >> 8), byte((nameLen + 3) & 0xff), // Server name list length
		0x00,                                     // Name type: host_name
		byte(nameLen >> 8), byte(nameLen & 0xff), // Host name length
	}
	return append(ext, nameBytes...)
}

// baseCipherSuites is the common set of cipher suites used in TLS probes.
// Does NOT include TLS_EMPTY_RENEGOTIATION_INFO_SCSV — probes that need
// it must append 0x00, 0xff explicitly to avoid conflating signals.
var baseCipherSuites = []byte{
	0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	0x00, 0x9e, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
	0x00, 0x9f, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
	0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
	0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
	0x00, 0x0a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
}

// buildClientHello constructs a TLS ClientHello handshake message.
func buildClientHello(versionMajor, versionMinor byte, cipherSuites, extensions, compressionMethods []byte) []byte {
	random := make([]byte, 32)
	_, _ = rand.Read(random)

	// Session ID: empty
	sessionID := []byte{0x00}

	// Cipher suites length (2 bytes) + cipher suites
	cipherSuitesBlock := append([]byte{byte(len(cipherSuites) >> 8), byte(len(cipherSuites) & 0xff)}, cipherSuites...)

	// Compression methods length (1 byte) + methods
	compressionBlock := append([]byte{byte(len(compressionMethods))}, compressionMethods...)

	// Assemble ClientHello body: version(2) + random(32) + session_id + cipher_suites + compression
	body := []byte{versionMajor, versionMinor}
	body = append(body, random...)
	body = append(body, sessionID...)
	body = append(body, cipherSuitesBlock...)
	body = append(body, compressionBlock...)

	if len(extensions) > 0 {
		body = append(body, byte(len(extensions)>>8), byte(len(extensions)&0xff))
		body = append(body, extensions...)
	}

	// Handshake header: type(1) + length(3)
	handshake := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body) & 0xff)}
	return append(handshake, body...)
}

// buildTLSRecord wraps a payload in a TLS record header.
func buildTLSRecord(contentType, versionMajor, versionMinor byte, payload []byte) []byte {
	header := []byte{contentType, versionMajor, versionMinor, byte(len(payload) >> 8), byte(len(payload) & 0xff)}
	return append(header, payload...)
}

// sendJARMProbe opens a TCP connection, sends payload, and reads one response buffer.
// Returns nil on any error. This mirrors the probeSSLv3 transport pattern.
func sendJARMProbe(target string, payload []byte, timeout time.Duration) []byte {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(payload); err != nil {
		return nil
	}
	resp := make([]byte, 1484)
	n, _ := conn.Read(resp)
	return resp[:n]
}

// computeJARM sends the 10 standard JARM probes and returns the resulting 62-character hash.
// Returns jarm.ZeroHash if the target is unreachable or does not respond to any probe.
func computeJARM(target string, timeout time.Duration) string {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return jarm.ZeroHash
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return jarm.ZeroHash
	}
	probes := jarm.GetProbes(host, port)
	rawResults := make([]string, 0, len(probes))
	for _, probe := range probes {
		payload := jarm.BuildProbe(probe)
		resp := sendJARMProbe(target, payload, timeout)
		result, _ := jarm.ParseServerHello(resp, probe)
		rawResults = append(rawResults, result)
	}
	return jarm.RawHashToFuzzyHash(strings.Join(rawResults, ","))
}

// tlsVersionCode maps a TLS version uint16 to its 2-character JA4 version code.
func tlsVersionCode(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "13"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS10:
		return "10"
	case tls.VersionSSL30:
		return "s3"
	default:
		return "00"
	}
}

// computeJA4S connects to target, sends a TLS 1.3-capable ClientHello, reads the
// ServerHello, and returns the JA4S fingerprint string. Returns "" on failure.
//
// JA4S format: t{TLSVersion}{CipherCount}{ALPN}_{SelectedCipher}_{ExtensionHash}
//
//   - TLSVersion: 2-char code ("13" = TLS 1.3, "12" = TLS 1.2, etc.)
//   - CipherCount: number of cipher suites in the ServerHello (always "01")
//   - ALPN: first 2 chars of selected ALPN protocol, or "00" if absent
//   - SelectedCipher: selected cipher suite as 4-hex lowercase
//   - ExtensionHash: lowercase SHA-256 of comma-joined sorted extension type
//     decimal strings, truncated to 12 chars
func computeJA4S(target, serverName string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Build a TLS 1.3 ClientHello that also supports TLS 1.2.
	sniExt := buildSNIExtension(serverName)

	// supported_versions extension (0x002b): offer TLS 1.3 + TLS 1.2
	suppVersExt := []byte{
		0x00, 0x2b, // type: supported_versions
		0x00, 0x05, // ext length
		0x04,       // versions list length
		0x03, 0x04, // TLS 1.3
		0x03, 0x03, // TLS 1.2
	}
	// supported_groups extension (0x000a): x25519, secp256r1, secp384r1
	suppGroupsExt := []byte{
		0x00, 0x0a, // type: supported_groups
		0x00, 0x08, // ext length
		0x00, 0x06, // groups list length
		0x00, 0x1d, // x25519
		0x00, 0x17, // secp256r1
		0x00, 0x18, // secp384r1
	}

	// key_share extension (0x0033): required for TLS 1.3 – without it a pure
	// TLS 1.3 server responds with HelloRetryRequest (handshake type 0x02,
	// identical to ServerHello) instead of a full ServerHello.
	keyShareExt := []byte{
		0x00, 0x33, // type: key_share
		0x00, 0x26, // ext data length = 38
		0x00, 0x24, // key_share_list length = 36
		0x00, 0x1d, // group: x25519
		0x00, 0x20, // key_exchange length = 32
		// 32-byte placeholder x25519 public key (zeroes are fine for fingerprinting)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// ALPN extension (0x0010): offer h2 and http/1.1 so servers that support
	// ALPN will select and return their preferred protocol in the ServerHello.
	// Without this, the probe never elicits an ALPN extension in the response
	// and the JA4S ALPN field is always "00" even for HTTP/2-capable servers.
	alpnExt := []byte{
		0x00, 0x10, // type: ALPN
		0x00, 0x0e, // ext data length = 14
		0x00, 0x0c, // protocol_name_list length = 12
		0x02,                                           // "h2" length
		0x68, 0x32,                                     // "h2"
		0x08,                                           // "http/1.1" length
		0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, // "http/1.1"
	}

	var extensions []byte
	extensions = append(extensions, sniExt...)
	extensions = append(extensions, alpnExt...)
	extensions = append(extensions, suppVersExt...)
	extensions = append(extensions, suppGroupsExt...)
	extensions = append(extensions, keyShareExt...)

	hello := buildClientHello(0x03, 0x03, baseCipherSuites, extensions, []byte{0x00})
	record := buildTLSRecord(0x16, 0x03, 0x01, hello)

	if _, err := conn.Write(record); err != nil {
		return ""
	}

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	// Must be a TLS Handshake (0x16) containing a ServerHello (0x02)
	if n < 44 || buf[0] != 0x16 || buf[5] != 0x02 {
		return ""
	}
	// Detect HelloRetryRequest: same handshake type (0x02) as ServerHello but
	// carries a special 32-byte magic Random (SHA-256 of "HelloRetryRequest").
	// This happens when the server rejects all offered key_share groups.
	const shBase = 9 // TLS record (5) + handshake header (4)
	if n >= shBase+34 {
		hrrMagic := [32]byte{
			0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
			0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
			0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
			0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
		}
		var random [32]byte
		copy(random[:], buf[shBase+2:shBase+34])
		if random == hrrMagic {
			return "" // HelloRetryRequest — cannot fingerprint
		}
	}

	return parseJA4SFromServerHello(buf[:n])
}

// parseJA4SFromServerHello extracts the JA4S fingerprint from raw ServerHello bytes.
func parseJA4SFromServerHello(data []byte) string {
	// TLS record header: 5 bytes. Handshake header: 4 bytes. ServerHello starts at offset 9.
	shOffset := 9
	if len(data) < shOffset+35 {
		return ""
	}

	rawVersion := uint16(data[shOffset])<<8 | uint16(data[shOffset+1])
	verCode := tlsVersionCode(rawVersion)

	// Random is 32 bytes at shOffset+2. session_id_len at shOffset+34.
	sessionIDLen := int(data[shOffset+34])

	cipherOffset := shOffset + 34 + 1 + sessionIDLen
	if len(data) < cipherOffset+3 {
		return ""
	}
	selectedCipher := fmt.Sprintf("%04x", uint16(data[cipherOffset])<<8|uint16(data[cipherOffset+1]))
	// compression method at cipherOffset+2 (skip)

	extListOffset := cipherOffset + 3
	if len(data) < extListOffset+2 {
		// No extensions present
		return fmt.Sprintf("t%s0100_%s_000000000000", verCode, selectedCipher)
	}

	extListLen := int(data[extListOffset])<<8 | int(data[extListOffset+1])
	extOffset := extListOffset + 2
	extEnd := extOffset + extListLen
	if extEnd > len(data) {
		// Extension list is truncated — partial extension types would produce
		// an incorrect fingerprint that differs from the full-read result.
		return ""
	}

	var extTypes []int
	alpn := "00"
	for extOffset+4 <= extEnd {
		extType := int(uint16(data[extOffset])<<8 | uint16(data[extOffset+1]))
		extLen := int(data[extOffset+2])<<8 | int(data[extOffset+3])
		extTypes = append(extTypes, extType)

		// ALPN extension type 0x0010
		if extType == 0x0010 && extOffset+4+extLen <= extEnd {
			alpnData := data[extOffset+4 : extOffset+4+extLen]
			// alpnData layout (RFC 7301, same in ClientHello and ServerHello):
			//   proto_list_len(2) | proto_len(1) | proto_name
			if len(alpnData) >= 4 {
				protoLen := int(alpnData[2])
				if protoLen > 0 && len(alpnData) >= 3+protoLen {
					protoName := string(alpnData[3 : 3+protoLen])
					if len(protoName) >= 2 {
						alpn = protoName[:2]
					} else {
						alpn = protoName
					}
				}
			}
		}

		// supported_versions extension type 0x002b
		// In a ServerHello this carries a single 2-byte selected version (RFC 8446
		// §4.2.1).  TLS 1.3 mandates legacy_version == 0x0303, so the real
		// negotiated version MUST be read from here — reading legacy_version
		// alone would always yield "12" for TLS 1.3.
		if extType == 0x002b && extOffset+4+extLen <= extEnd && extLen >= 2 {
			selectedVer := uint16(data[extOffset+4])<<8 | uint16(data[extOffset+5])
			if code := tlsVersionCode(selectedVer); code != "00" {
				verCode = code
			}
		}

		extOffset += 4 + extLen
	}

	sort.Ints(extTypes)
	extStrs := make([]string, len(extTypes))
	for i, t := range extTypes {
		extStrs[i] = strconv.Itoa(t)
	}
	h := sha256.Sum256([]byte(strings.Join(extStrs, ",")))
	extHash := hex.EncodeToString(h[:])[:12]

	// CipherCount in a ServerHello is always 1, formatted as 2-digit decimal.
	return fmt.Sprintf("t%s01%s_%s_%s", verCode, alpn, selectedCipher, extHash)
}

// computeJA4XForCert computes the JA4X fingerprint for a single X.509 certificate.
//
// JA4X format: {IssuerHash}_{SubjectHash}_{PublicKeyHash}
//
//   - IssuerHash:    SHA-256 of DER-encoded issuer distinguished name, truncated to 12 hex chars
//   - SubjectHash:   SHA-256 of DER-encoded subject distinguished name, truncated to 12 hex chars
//   - PublicKeyHash: SHA-256 of DER-encoded SubjectPublicKeyInfo, truncated to 12 hex chars
func computeJA4XForCert(cert *x509.Certificate) string {
	issuerHash := sha256.Sum256(cert.RawIssuer)
	subjectHash := sha256.Sum256(cert.RawSubject)
	pubKeyHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)

	return fmt.Sprintf("%s_%s_%s",
		hex.EncodeToString(issuerHash[:])[:12],
		hex.EncodeToString(subjectHash[:])[:12],
		hex.EncodeToString(pubKeyHash[:])[:12],
	)
}
