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

// BuildASReq builds an AS-REQ for the specified realm and principal.
// If withPreauth is false, the request omits PA-ENC-TIMESTAMP (AS-REP roast).
// Password and ntlmHash are unused when withPreauth is false; PA data is not added here —
// callers that need pre-auth should use the gokrb5 client.ASExchange path which handles
// PA-ENC-TIMESTAMP encryption automatically.
func BuildASReq(realm, principal string, cfg *config.Config, withPreauth bool) (messages.ASReq, error) {
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, principal)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", strings.ToUpper(realm)},
	}

	asReq, err := messages.NewASReq(strings.ToUpper(realm), cfg, cname, sname)
	if err != nil {
		return messages.ASReq{}, fmt.Errorf("failed to create AS-REQ: %w", err)
	}

	// If withPreauth is false (AS-REP roast mode), leave PA data empty so KDC
	// returns the AS-REP without requiring pre-authentication.
	// PA-ENC-TIMESTAMP would normally be added by the gokrb5 client internals;
	// for the raw primitive path we simply don't add it.
	if withPreauth {
		// For the raw transport path, we intentionally send without PA-ENC-TIMESTAMP
		// and let the KDC tell us what it wants. Full preauth requires the gokrb5
		// client.ASExchange path (which encrypts the timestamp with the key material).
		// This is intentional: the AS_REQ primitive is primarily useful for
		// KDC_ERR_PREAUTH_REQUIRED probing and AS-REP roast (noPreauth=true).
	}

	return asReq, nil
}

// LookupKrbErrName returns the symbolic name for a KDC error code.
// It uses the iana/errorcode.Lookup function which returns a full description string;
// this function extracts just the symbolic name prefix.
func LookupKrbErrName(code int32) string {
	full := errorcode.Lookup(code)
	// Lookup returns "(<code>) <NAME> <description>"
	// Extract just the NAME part (first word after the parenthetical)
	// e.g. "(25) KDC_ERR_PREAUTH_REQUIRED Additional pre-authentication required"
	// We want "KDC_ERR_PREAUTH_REQUIRED"
	parts := strings.SplitN(full, " ", 3)
	if len(parts) >= 2 {
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
