package pop3

import (
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
)

// TODO(AITF-56 follow-up): SASL mechanism normalization is now duplicated
// across SMTP, POP3, and IMAP enumerators.  internal/protocol/sasl/ exists as
// a shared package (added by IMAP #281); migrate POP3's mapping onto it before
// the next mail protocol lands (SIEVE, JMAP, etc.).  Each enumerator should
// then only translate the shared sasl.Mechanism into its own Fern enum type
// rather than parsing raw strings independently.

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
