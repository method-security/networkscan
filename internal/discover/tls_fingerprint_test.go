// Package discover tests for TLS fingerprinting functions (JA4S, JARM, JA4X).
package discover

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	jarm "github.com/hdm/jarm-go"
)

// buildTestServerHello constructs a minimal TLS 1.2 ServerHello for unit testing.
//
// Layout:
//
//	TLS record header (5 bytes): 0x16 0x03 0x03 <len-hi> <len-lo>
//	Handshake header  (4 bytes): 0x02 <len-hi2> <len-mid> <len-lo>
//	ServerHello body:
//	  version(2) | random(32) | session_id_len(1) | cipher(2) | compression(1)
//	  | ext_list_len(2) | <extensions>
func buildTestServerHello(version []byte, cipher []byte, extensions []byte) []byte {
	// ServerHello body
	body := make([]byte, 0, 2+32+1+2+1+2+len(extensions))
	body = append(body, version...)          // version (2 bytes)
	body = append(body, make([]byte, 32)...) // random (32 zero bytes)
	body = append(body, 0x00)                // session_id_len = 0
	body = append(body, cipher...)           // cipher suite (2 bytes)
	body = append(body, 0x00)                // compression = null

	if len(extensions) > 0 {
		extLen := len(extensions)
		body = append(body, byte(extLen>>8), byte(extLen&0xff))
		body = append(body, extensions...)
	}

	// Handshake header: type(1) = 0x02 (ServerHello) + length(3)
	hsLen := len(body)
	hs := []byte{0x02, byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen & 0xff)}
	hs = append(hs, body...)

	// TLS record header: type(1)=0x16, version(2), length(2)
	recLen := len(hs)
	rec := []byte{0x16, 0x03, 0x03, byte(recLen >> 8), byte(recLen & 0xff)}
	rec = append(rec, hs...)
	return rec
}

// buildALPNExtension encodes a single ALPN extension carrying one protocol name.
func buildALPNExtension(proto string) []byte {
	p := []byte(proto)
	// proto list entry: len(1) + proto
	entry := append([]byte{byte(len(p))}, p...)
	// proto list: len(2) + entry
	protoList := append([]byte{0x00, byte(len(entry))}, entry...)
	// extension: type(2) + ext_len(2) + protoList
	ext := []byte{0x00, 0x10, 0x00, byte(len(protoList))}
	return append(ext, protoList...)
}

// TestParseJA4SFromServerHello_TLS12_WithALPN validates JA4S parsing for a
// synthetic TLS 1.2 ServerHello that selects cipher 0xc02b and ALPN "h2".
func TestParseJA4SFromServerHello_TLS12_WithALPN(t *testing.T) {
	t.Parallel()
	alpnExt := buildALPNExtension("h2")
	record := buildTestServerHello(
		[]byte{0x03, 0x03}, // TLS 1.2
		[]byte{0xc0, 0x2b}, // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		alpnExt,
	)

	result := parseJA4SFromServerHello(record)
	if result == "" {
		t.Fatal("parseJA4SFromServerHello returned empty string")
	}

	// Structure check: t<version><count><alpn>_<cipher>_<hash>
	parts := strings.Split(result, "_")
	if len(parts) != 3 {
		t.Fatalf("expected 3 underscore-separated parts, got %d: %s", len(parts), result)
	}

	prefix := parts[0]
	if !strings.HasPrefix(prefix, "t") {
		t.Errorf("expected 't' TCP prefix, got %q", result)
	}
	// version = "12", count = "01" (ALPN counted), alpn = "h2" → prefix = "t1201h2".
	// JA4S ALPN = first + last char of selected protocol: "h2"[0]+"h2"[1] = "h2".
	if prefix != "t1201h2" {
		t.Errorf("expected prefix t1201h2, got %q", prefix)
	}
	if parts[1] != "c02b" {
		t.Errorf("expected cipher c02b, got %q", parts[1])
	}
	if len(parts[2]) != 12 {
		t.Errorf("expected 12-char extension hash, got %d chars: %q", len(parts[2]), parts[2])
	}

	// JA4S_c excludes ALPN (0x0010) from the hash input (per FoxIO JA4S spec),
	// and uses wire order (not sorted). With only the ALPN extension present,
	// hashExtTypes is empty → SHA256("").
	h := sha256.Sum256([]byte(""))
	wantExtHash := hex.EncodeToString(h[:])[:12]
	if parts[2] != wantExtHash {
		t.Errorf("extension hash: want %q (sha256(\"\")[:12], ALPN excluded), got %q", wantExtHash, parts[2])
	}
}

// TestParseJA4SFromServerHello_TLS13_NoALPN checks a TLS 1.3 ServerHello.
// Per RFC 8446 §4.1.3 the legacy_version field MUST be 0x0303 and the actual
// negotiated version is carried in the supported_versions extension (0x002b).
// The fingerprint must therefore report version "13", not "12".
func TestParseJA4SFromServerHello_TLS13_NoALPN(t *testing.T) {
	t.Parallel()
	// supported_versions extension: selected version = TLS 1.3 (0x0304)
	suppVersExt := []byte{
		0x00, 0x2b, // type: supported_versions
		0x00, 0x02, // ext data length = 2
		0x03, 0x04, // TLS 1.3 selected version
	}
	record := buildTestServerHello(
		[]byte{0x03, 0x03}, // legacy_version (always 0x0303 in real TLS 1.3 ServerHello)
		[]byte{0x13, 0x01}, // TLS_AES_128_GCM_SHA256
		suppVersExt,
	)

	result := parseJA4SFromServerHello(record)
	if result == "" {
		t.Fatal("parseJA4SFromServerHello returned empty string")
	}

	// Expected format: t130100_1301_<extHash>
	//   version="13" (from supported_versions ext), count="01", alpn="00" (no ALPN)
	parts := strings.Split(result, "_")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d: %s", len(parts), result)
	}
	if parts[0] != "t130100" {
		t.Errorf("expected prefix t130100 (version from supported_versions ext), got %q", parts[0])
	}
	if parts[1] != "1301" {
		t.Errorf("expected cipher 1301, got %q", parts[1])
	}
	// Extension hash: wire-order ext types (GREASE/SNI/ALPN excluded) = [43]
	// (0x002b = 43, supported_versions). JA4S uses wire order not sorted order.
	h := sha256.Sum256([]byte("43"))
	wantExtHash := hex.EncodeToString(h[:])[:12]
	if parts[2] != wantExtHash {
		t.Errorf("extension hash: want %q (sha256(\"43\")[:12], wire order), got %q", wantExtHash, parts[2])
	}
}

// TestParseJA4SFromServerHello_TooShort ensures that truncated data returns "".
func TestParseJA4SFromServerHello_TooShort(t *testing.T) {
	t.Parallel()
	result := parseJA4SFromServerHello([]byte{0x16, 0x03, 0x03, 0x00, 0x05})
	if result != "" {
		t.Errorf("expected empty string for truncated input, got %q", result)
	}
}

// TestComputeJA4XForCert validates the JA4X format for a synthetic X.509 cert.
func TestComputeJA4XForCert(t *testing.T) {
	t.Parallel()

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test",
			Organization: []string{"TestOrg"},
		},
		Issuer: pkix.Name{
			CommonName:   "testca",
			Organization: []string{"TestCA"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		// RawIssuer and RawSubject will be nil for a manually constructed cert,
		// so we set them explicitly to non-nil slices for a stable test.
		RawIssuer:               []byte("testca-issuer"),
		RawSubject:              []byte("test-subject"),
		RawSubjectPublicKeyInfo: []byte("test-pubkey"),
	}

	result := computeJA4XForCert(cert)

	// Verify format: 3 underscore-separated 12-hex-char segments.
	parts := strings.Split(result, "_")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d: %q", len(parts), result)
	}
	for i, p := range parts {
		if len(p) != 12 {
			t.Errorf("part[%d] has length %d, want 12: %q", i, len(p), p)
		}
		// Must be valid lowercase hex.
		if _, err := hex.DecodeString(p); err != nil {
			t.Errorf("part[%d] is not valid hex: %q", i, p)
		}
	}

	// Verify the issuer hash segment against the known-good SHA-256.
	issuerHash := sha256.Sum256([]byte("testca-issuer"))
	wantIssuer := hex.EncodeToString(issuerHash[:])[:12]
	if parts[0] != wantIssuer {
		t.Errorf("issuer hash: want %q, got %q", wantIssuer, parts[0])
	}

	subjectHash := sha256.Sum256([]byte("test-subject"))
	wantSubject := hex.EncodeToString(subjectHash[:])[:12]
	if parts[1] != wantSubject {
		t.Errorf("subject hash: want %q, got %q", wantSubject, parts[1])
	}

	pubKeyHash := sha256.Sum256([]byte("test-pubkey"))
	wantPubKey := hex.EncodeToString(pubKeyHash[:])[:12]
	if parts[2] != wantPubKey {
		t.Errorf("pubkey hash: want %q, got %q", wantPubKey, parts[2])
	}
}

// TestJARMZeroHash verifies that jarm.RawHashToFuzzyHash returns the expected
// 62-char zero hash when all 10 probes return empty responses.
func TestJARMZeroHash(t *testing.T) {
	t.Parallel()
	// Simulating 10 probes all returning "|||" (empty cipher|version|alpn|extlist).
	// The raw string jarm.RawHashToFuzzyHash treats as the all-zeros sentinel:
	raw := "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||"
	got := jarm.RawHashToFuzzyHash(raw)
	if got != jarm.ZeroHash {
		t.Errorf("expected zero hash %q, got %q", jarm.ZeroHash, got)
	}
	if len(got) != 62 {
		t.Errorf("JARM hash length: want 62, got %d", len(got))
	}
}

// TestJARMHashLength verifies that non-zero JARM hashes are always 62 chars.
func TestJARMHashLength(t *testing.T) {
	t.Parallel()
	// Use a known-stable raw probe result (taken from Salesforce JARM test vectors).
	// Each component: cipher(2)|version(1)|alpn(?)|extlist(?)
	// Here we use the canonical "unknown server" all-zeros responses.
	raw := "0000|0000|00|0000,0000|0000|00|0000,0000|0000|00|0000,0000|0000|00|0000,0000|0000|00|0000,0000|0000|00|0000,0000|0000|00|0000,0000|0000|00|0000,0000|0000|00|0000,0000|0000|00|0000"
	got := jarm.RawHashToFuzzyHash(raw)
	if len(got) != 62 {
		t.Errorf("JARM hash length: want 62, got %d: %q", len(got), got)
	}
}

// TestTLSVersionCode checks the 2-char version codes used in JA4S fingerprints.
func TestTLSVersionCode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		version uint16
		want    string
	}{
		{0x0304, "13"}, // TLS 1.3
		{0x0303, "12"}, // TLS 1.2
		{0x0302, "11"}, // TLS 1.1
		{0x0301, "10"}, // TLS 1.0
		{0x0300, "s3"}, // SSL 3.0
		{0xffff, "00"}, // unknown
	}
	for _, c := range cases {
		got := tlsVersionCode(c.version)
		if got != c.want {
			t.Errorf("tlsVersionCode(0x%04x) = %q, want %q", c.version, got, c.want)
		}
	}
}
