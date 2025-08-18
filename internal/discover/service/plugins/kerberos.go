// Package plugins provides Kerberos service fingerprinting for stealth mode
package plugins

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/utils"
	"github.com/jfjallid/gokrb5/v8/config"
	"github.com/jfjallid/gokrb5/v8/iana/nametype"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/types"
	plugins "github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils_fx "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

/* ---------- metadata types ---------- */

type Metadata struct {
	KRBMessage string `json:"krbMessage"`          // AS_REP or KRB_ERROR
	ErrorCode  int32  `json:"errorCode,omitempty"` // if KRB_ERROR
}

func (Metadata) Type() string { return "kerberos" }

/* ---------- stealth mode fingerprinter ---------- */

type KerberosFingerprinter struct{}

func (KerberosFingerprinter) Name() string { return "kerberos" }

func (KerberosFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Create a context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	addr := fmt.Sprintf("%s:%d", ip, port)
	timeoutDuration := time.Duration(timeout) * time.Second

	// Create fingerprintx target
	addrPort := netip.AddrPortFrom(netip.MustParseAddr(ip.String()), uint16(port))
	fxTarget := plugins.Target{Address: addrPort, Host: host}

	// Try plaintext connection
	var d net.Dialer
	conn, err := d.DialContext(timeoutCtx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Try Kerberos detection on plaintext connection
	fxResult, err := detectKerberos(conn, fxTarget, timeoutDuration, false)
	if err != nil || fxResult == nil {
		// Try with TLS if plaintext failed
		_ = conn.Close()
		conn, err = d.DialContext(timeoutCtx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		defer func() { _ = conn.Close() }()

		fxResult, err = detectKerberos(conn, fxTarget, timeoutDuration, true)
		if err != nil || fxResult == nil {
			return nil, fmt.Errorf("no Kerberos service detected")
		}
	}

	// Convert fingerprintx result to stealth format
	return &discoverfern.ServiceDetails{
		Host:      fxResult.Host,
		Ip:        fxResult.IP,
		Port:      fxResult.Port,
		Tls:       fxResult.TLS,
		Transport: utils.GetTransportTypeEnum(strings.ToUpper(fxResult.Transport)),
		Protocol:  utils.GetProtocolTypeEnum(strings.ToUpper(fxResult.Protocol)),
		Version:   &fxResult.Version,
		Metadata:  convertFxMetadata(fxResult.Raw),
	}, nil
}

/* ---------- detector (same as fingerprintx) ---------- */

func detectKerberos(conn net.Conn, tgt plugins.Target, timeout time.Duration, tlsMode bool) (*plugins.Service, error) {
	if tlsMode {
		tc := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         tgt.Host,
		})
		if err := tc.Handshake(); err != nil {
			return nil, nil
		}
		conn = tc
	}

	packet, err := buildASReq(tgt.Host)
	if err != nil {
		return nil, err
	}

	reply, err := utils_fx.SendRecv(conn, packet, timeout)
	if err != nil || len(reply) < 5 {
		return nil, nil
	}

	tag := reply[4]                 // first ASN.1 tag after 4‑byte length
	if tag != 0x6A && tag != 0x7E { // 0x6A AS_REP, 0x7E KRB_ERROR
		return nil, nil
	}

	meta := Metadata{KRBMessage: map[byte]string{0x6A: "AS_REP", 0x7E: "KRB_ERROR"}[tag]}
	if tag == 0x7E && len(reply) > 9 {
		meta.ErrorCode = int32(binary.BigEndian.Uint32(reply[len(reply)-4:]))
	}

	transport := plugins.TCP
	if tlsMode {
		transport = plugins.TCPTLS
	}
	return plugins.CreateServiceFrom(tgt, meta, tlsMode, "", transport), nil
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

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, uint32(len(raw))); err != nil {
		return nil, err
	}
	buf.Write(raw)
	return buf.Bytes(), nil
}

/* ---------- helper functions ---------- */

// convertFxMetadata converts fingerprintx raw JSON to map[string]string
func convertFxMetadata(raw []byte) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	
	// Parse the JSON metadata from fingerprintx
	var metadata map[string]interface{}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return nil
	}
	
	result := make(map[string]string)
	for k, v := range metadata {
		result[k] = fmt.Sprintf("%v", v)
	}
	return result
}