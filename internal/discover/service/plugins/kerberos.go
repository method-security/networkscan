// Package plugins provides Kerberos service fingerprinting for stealth mode
package plugins

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/jfjallid/gokrb5/v8/config"
	"github.com/jfjallid/gokrb5/v8/iana/nametype"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/types"
)

/* ---------- stealth mode fingerprinter ---------- */

type KerberosFingerprinter struct{}

func (KerberosFingerprinter) Name() string { return "kerberos" }

func (KerberosFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Create a context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	addr := fmt.Sprintf("%s:%d", ip, port)
	timeoutDuration := time.Duration(timeout) * time.Second

	// Try plaintext connection first
	var d net.Dialer
	conn, err := d.DialContext(timeoutCtx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Try Kerberos detection on plaintext connection
	result, tlsUsed, err := detectKerberos(conn, host, timeoutDuration, false)
	if err != nil || !result {
		// Try with TLS if plaintext failed
		_ = conn.Close()
		conn, err = d.DialContext(timeoutCtx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		defer func() { _ = conn.Close() }()

		result, tlsUsed, err = detectKerberos(conn, host, timeoutDuration, true)
		if err != nil || !result {
			return nil, fmt.Errorf("no Kerberos service detected")
		}
	}

	// Build service details
	transport := common.TransportTypeTcp
	if tlsUsed {
		transport = common.TransportTypeTcptls
	}

	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       tlsUsed,
		Transport: transport,
		Protocol:  common.ProtocolTypeKerberos,
		Version:   nil,
		Metadata:  map[string]string{"detected": "kerberos"},
	}, nil
}

/* ---------- detection logic ---------- */

func detectKerberos(conn net.Conn, realm string, timeout time.Duration, tlsMode bool) (bool, bool, error) {
	if tlsMode {
		tc := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         realm,
		})
		if err := tc.Handshake(); err != nil {
			return false, false, err
		}
		conn = tc
	}

	packet, err := buildASReq(realm)
	if err != nil {
		return false, tlsMode, err
	}

	// Send the packet
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return false, tlsMode, err
	}
	_, err = conn.Write(packet)
	if err != nil {
		return false, tlsMode, err
	}

	// Read response
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return false, tlsMode, err
	}

	// Read the 4-byte length header first
	lengthBuf := make([]byte, 4)
	_, err = conn.Read(lengthBuf)
	if err != nil {
		return false, tlsMode, err
	}

	// Read the actual response
	length := binary.BigEndian.Uint32(lengthBuf)
	if length == 0 || length > 65535 { // reasonable bounds
		return false, tlsMode, fmt.Errorf("invalid response length")
	}

	response := make([]byte, length)
	_, err = conn.Read(response)
	if err != nil {
		return false, tlsMode, err
	}

	// Check if it's a valid Kerberos response
	if len(response) < 1 {
		return false, tlsMode, fmt.Errorf("response too short")
	}

	// Look for Kerberos ASN.1 tags (AS_REP: 0x6A, KRB_ERROR: 0x7E)
	tag := response[0]
	if tag == 0x6A || tag == 0x7E {
		return true, tlsMode, nil
	}

	return false, tlsMode, fmt.Errorf("not a Kerberos response")
}

/* ---------- helper: minimal anonymous AS‑REQ ---------- */

func buildASReq(realm string) ([]byte, error) {
	// Create minimal config
	cfg := config.New()
	cfg.LibDefaults.Forwardable = true

	// Create client principal name (nonexistent user)
	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"testuser"},
	}

	// Create service principal name (krbtgt)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}

	asReq, err := messages.NewASReq(realm, cfg, cname, sname)
	if err != nil {
		return nil, err
	}

	raw, err := asReq.Marshal()
	if err != nil {
		return nil, err
	}

	// Prepend 4-byte length header (TCP format)
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, uint32(len(raw))); err != nil {
		return nil, err
	}
	buf.Write(raw)
	return buf.Bytes(), nil
}
