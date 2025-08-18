// Package fingerprintx provides Kerberos service fingerprinting for fingerprintx
package fingerprintx

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"time"

	"github.com/jfjallid/gokrb5/v8/config"
	"github.com/jfjallid/gokrb5/v8/iana/nametype"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/types"
	plugins "github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

/* ---------- metadata ---------- */

type Metadata struct {
	KRBMessage string `json:"krbMessage"`          // AS_REP or KRB_ERROR
	ErrorCode  int32  `json:"errorCode,omitempty"` // if KRB_ERROR
}

func (Metadata) Type() string { return "kerberos" }

/* ---------- plug‑ins ---------- */

type Plugin struct{}
type TLSPlugin struct{}

func (p *Plugin) Name() string    { return "kerberos" }
func (p *TLSPlugin) Name() string { return "kerberos_tls" } // distinct

func (p *Plugin) Type() plugins.Protocol    { return plugins.TCP }
func (p *TLSPlugin) Type() plugins.Protocol { return plugins.TCPTLS }

func (p *Plugin) PortPriority(port uint16) bool    { return port == 88 || port == 6565 }
func (p *TLSPlugin) PortPriority(port uint16) bool { return port == 88 || port == 464 }

func (p *Plugin) Priority() int    { return 90 }
func (p *TLSPlugin) Priority() int { return 91 }

func init() {
	plugins.RegisterPlugin(&Plugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

/* ---------- runtime ---------- */

func (p *Plugin) Run(conn net.Conn, t time.Duration, tgt plugins.Target) (*plugins.Service, error) {
	return detectKerberos(conn, tgt, t, false)
}
func (p *TLSPlugin) Run(conn net.Conn, t time.Duration, tgt plugins.Target) (*plugins.Service, error) {
	return detectKerberos(conn, tgt, t, true)
}

/* ---------- detector ---------- */

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

	reply, err := utils.SendRecv(conn, packet, timeout)
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
