package plugins

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"unicode/utf8"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	ber "github.com/go-asn1-ber/asn1-ber"
)

// LDAPDiscoveryFingerprinter leaves the original LDAPFingerprinter unchanged.
type LDAPDiscoveryFingerprinter struct{}
type LDAPTLSFingerprinter struct{}

func (LDAPDiscoveryFingerprinter) Name() string        { return "ldap" }
func (LDAPTLSFingerprinter) Name() string              { return "ldaps" }
func (LDAPDiscoveryFingerprinter) DefaultPorts() []int { return []int{389} }
func (LDAPTLSFingerprinter) DefaultPorts() []int       { return []int{636} }
func (LDAPDiscoveryFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativeLDAP(ctx, ip, port, host, timeout, false)
}
func (LDAPTLSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return detectNativeLDAP(ctx, ip, port, host, timeout, true)
}

// RFC 4511 sections 4.2 and 5.1: LDAPv3 anonymous bind, definite-length BER.
func detectNativeLDAP(ctx context.Context, ip net.IP, port int, host string, timeout int, secure bool) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, err := helpers.TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	protocol, name := common.ProtocolTypeLdap, "ldap"
	if secure {
		upgraded, e := helpers.UpgradeTLS(ctx, conn, host)
		if e != nil {
			return nil, e
		}
		conn = upgraded
		protocol, name = common.ProtocolTypeLdaps, "ldaps"
	}
	request := ber.NewSequence("")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, ""))
	bind := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "")
	bind.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, ""))
	bind.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	bind.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "", ""))
	request.AppendChild(bind)
	if _, err = conn.Write(request.Bytes()); err != nil {
		return nil, err
	}
	// Bound the envelope before the library sees any server-controlled lengths.
	var prefix [2]byte
	if _, err = io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	if prefix[0] != 0x30 {
		return nil, fmt.Errorf("not an LDAP sequence")
	}
	frame := append([]byte(nil), prefix[:]...)
	n := int(prefix[1])
	if n&128 != 0 {
		width := n & 127
		if width == 0 || width > 4 {
			return nil, fmt.Errorf("invalid LDAP BER length")
		}
		extra := make([]byte, width)
		if _, err = io.ReadFull(conn, extra); err != nil {
			return nil, err
		}
		frame = append(frame, extra...)
		n = 0
		for _, b := range extra {
			n = n<<8 | int(b)
		}
	}
	if n < 7 || n > 65536 {
		return nil, fmt.Errorf("LDAP response exceeds bounds")
	}
	body := make([]byte, n)
	if _, err = io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	frame = append(frame, body...)
	if err = nativeLDAPBERBounds(frame, 0); err != nil {
		return nil, err
	}
	message, err := ber.DecodePacketErr(frame)
	if err != nil {
		return nil, err
	}
	if len(message.Children) < 2 || len(message.Children) > 3 {
		return nil, fmt.Errorf("invalid LDAP envelope")
	}
	id, response := message.Children[0], message.Children[1]
	if id.ClassType != ber.ClassUniversal || id.TagType != ber.TypePrimitive || id.Tag != ber.TagInteger || id.Value != int64(1) || response.ClassType != ber.ClassApplication || response.TagType != ber.TypeConstructed || response.Tag != 1 || len(response.Children) < 3 || len(response.Children) > 5 {
		return nil, fmt.Errorf("not the requested LDAP BindResponse")
	}
	fields := response.Children
	if fields[0].ClassType != ber.ClassUniversal || fields[0].TagType != ber.TypePrimitive || fields[0].Tag != ber.TagEnumerated {
		return nil, fmt.Errorf("invalid LDAP result code")
	}
	code, ok := fields[0].Value.(int64)
	if !ok || code < 0 || code > 4096 {
		return nil, fmt.Errorf("invalid LDAP result value")
	}
	for _, field := range fields[1:3] {
		if field.ClassType != ber.ClassUniversal || field.TagType != ber.TypePrimitive || field.Tag != ber.TagOctetString || !utf8.Valid(field.Data.Bytes()) {
			return nil, fmt.Errorf("invalid LDAP result string")
		}
	}
	seen := map[ber.Tag]bool{}
	for _, field := range fields[3:] {
		if field.ClassType != ber.ClassContext || seen[field.Tag] {
			return nil, fmt.Errorf("invalid LDAP result extension")
		}
		seen[field.Tag] = true
		switch field.Tag {
		case 3:
			if field.TagType != ber.TypeConstructed || code != 10 || len(field.Children) == 0 {
				return nil, fmt.Errorf("invalid LDAP referral")
			}
			for _, uri := range field.Children {
				if uri.ClassType != ber.ClassUniversal || uri.TagType != ber.TypePrimitive || uri.Tag != ber.TagOctetString {
					return nil, fmt.Errorf("invalid LDAP referral URI")
				}
			}
		case 7:
			if field.TagType != ber.TypePrimitive {
				return nil, fmt.Errorf("invalid LDAP SASL field")
			}
		default:
			return nil, fmt.Errorf("unexpected LDAP result field")
		}
	}
	if len(message.Children) == 3 && !nativeLDAPControls(message.Children[2]) {
		return nil, fmt.Errorf("invalid LDAP controls")
	}
	metadata := map[string]string{"result_code": strconv.FormatInt(code, 10), "anonymous_bind_allowed": strconv.FormatBool(code == 0), "matched_dn": string(fields[1].Data.Bytes()), "diagnostic_message": string(fields[2].Data.Bytes())}
	result := helpers.GenericResult(host, ip, port, common.TransportTypeTcp, protocol, name, "3", metadata)
	result.Tls = &secure
	return result, nil
}

func nativeLDAPControls(p *ber.Packet) bool {
	if p.ClassType != ber.ClassContext || p.TagType != ber.TypeConstructed || p.Tag != 0 || len(p.Children) == 0 {
		return false
	}
	for _, c := range p.Children {
		if c.ClassType != ber.ClassUniversal || c.TagType != ber.TypeConstructed || c.Tag != ber.TagSequence || len(c.Children) < 1 || len(c.Children) > 3 {
			return false
		}
		oid := c.Children[0]
		if oid.ClassType != ber.ClassUniversal || oid.TagType != ber.TypePrimitive || oid.Tag != ber.TagOctetString || oid.Data.Len() == 0 {
			return false
		}
		for _, b := range oid.Data.Bytes() {
			if (b < '0' || b > '9') && b != '.' {
				return false
			}
		}
		rest := c.Children[1:]
		if len(rest) > 0 && rest[0].Tag == ber.TagBoolean {
			if rest[0].ClassType != ber.ClassUniversal || rest[0].TagType != ber.TypePrimitive || rest[0].Data.Len() != 1 {
				return false
			}
			rest = rest[1:]
		}
		if len(rest) > 1 {
			return false
		}
		if len(rest) == 1 && (rest[0].ClassType != ber.ClassUniversal || rest[0].TagType != ber.TypePrimitive || rest[0].Tag != ber.TagOctetString) {
			return false
		}
	}
	return true
}

// Validate nested lengths and depth before recursive BER decoding. LDAP uses
// only low tag numbers here and prohibits indefinite lengths (RFC 4511 5.1).
func nativeLDAPBERBounds(data []byte, depth int) error {
	if depth > 8 {
		return fmt.Errorf("LDAP BER nesting exceeds limit")
	}
	for len(data) > 0 {
		if len(data) < 2 || data[0]&31 == 31 {
			return fmt.Errorf("invalid LDAP BER tag")
		}
		tag, n, header := data[0], uint64(data[1]), 2
		if n&128 != 0 {
			width := int(n & 127)
			if width == 0 || width > 4 || len(data) < 2+width {
				return fmt.Errorf("invalid LDAP BER length")
			}
			header += width
			n = 0
			for _, b := range data[2:header] {
				n = n<<8 | uint64(b)
			}
		}
		if n > uint64(len(data)-header) {
			return io.ErrUnexpectedEOF
		}
		end := header + int(n)
		if tag&32 != 0 {
			if err := nativeLDAPBERBounds(data[header:end], depth+1); err != nil {
				return err
			}
		}
		data = data[end:]
	}
	return nil
}
