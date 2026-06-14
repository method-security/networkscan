package kerberos

import (
	"fmt"
	"strings"

	"github.com/jfjallid/gokrb5/v8/config"
	"github.com/jfjallid/gokrb5/v8/iana/errorcode"
	"github.com/jfjallid/gokrb5/v8/iana/nametype"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/types"
)

// BuildASReq builds a raw AS-REQ for the specified realm and principal.
// The raw primitive path always omits PA-ENC-TIMESTAMP — the KDC will respond
// with KDC_ERR_PREAUTH_REQUIRED for pre-auth-enabled accounts (the probe
// signal) or an AS-REP for pre-auth-disabled accounts (the AS-REP-roast
// condition). Callers that need real PA-ENC-TIMESTAMP must go through the
// gokrb5 client.ASExchange path which encrypts the timestamp with the
// principal's key material; that's not modeled here because the raw
// primitive is intentionally credential-free.
func BuildASReq(realm, principal string, cfg *config.Config) (messages.ASReq, error) {
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, principal)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", strings.ToUpper(realm)},
	}

	asReq, err := messages.NewASReq(strings.ToUpper(realm), cfg, cname, sname)
	if err != nil {
		return messages.ASReq{}, fmt.Errorf("failed to create AS-REQ: %w", err)
	}

	return asReq, nil
}

// LookupKrbErrName returns the symbolic name for a KDC error code.
// It uses the iana/errorcode.Lookup function which returns a full description string;
// this function extracts just the symbolic name prefix.
func LookupKrbErrName(code int32) string {
	full := errorcode.Lookup(code)
	// Lookup returns "(<code>) <NAME> <description>" for known codes, e.g.
	//   "(25) KDC_ERR_PREAUTH_REQUIRED Additional pre-authentication required"
	// → we want "KDC_ERR_PREAUTH_REQUIRED".
	// For unknown codes Lookup returns "Unknown ErrorCode <n>" — a naive
	// splitN+parts[1] would yield "ErrorCode", which is useless. Detect the
	// unknown-form sentinel and synthesize a code-bearing name instead so
	// callers can still discriminate.
	if strings.HasPrefix(full, "Unknown") {
		return fmt.Sprintf("UNKNOWN_ERROR_CODE_%d", code)
	}
	parts := strings.SplitN(full, " ", 3)
	if len(parts) >= 2 && strings.HasPrefix(parts[0], "(") {
		return parts[1]
	}
	return full
}

// KerberosEtypeFromString maps a KerberosEncryptionType string to the gokrb5 etype ID.
func KerberosEtypeFromString(name string) (int32, bool) {
	switch strings.ToUpper(name) {
	case "AES256_CTS_HMAC_SHA1_96":
		return 18, true // etypeID.AES256_CTS_HMAC_SHA1_96
	case "AES128_CTS_HMAC_SHA1_96":
		return 17, true // etypeID.AES128_CTS_HMAC_SHA1_96
	case "RC4_HMAC":
		return 23, true // etypeID.RC4_HMAC
	}
	return 0, false
}
