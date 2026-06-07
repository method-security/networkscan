package pop3

import (
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
)

// defaultPorts are the standard POP3 ports: 110 (plaintext/STARTTLS), 995 (implicit TLS).
var defaultPorts = []int{110, 995}

// saslMechanismMap maps SASL mechanism name strings to the Fern enum values.
var saslMechanismMap = map[string]protocol.Pop3AuthMechanism{
	"PLAIN":         protocol.Pop3AuthMechanismPlain,
	"LOGIN":         protocol.Pop3AuthMechanismLogin,
	"CRAM-MD5":      protocol.Pop3AuthMechanismCrammd5,
	"SCRAM-SHA-1":   protocol.Pop3AuthMechanismScramsha1,
	"SCRAM-SHA-256": protocol.Pop3AuthMechanismScramsha256,
	"NTLM":          protocol.Pop3AuthMechanismNtlm,
	"GSSAPI":        protocol.Pop3AuthMechanismGssapi,
}
