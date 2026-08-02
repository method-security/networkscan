package client

import (
	"fmt"

	"github.com/jfjallid/gokrb5/v9/iana/errorcode"
	"github.com/jfjallid/gokrb5/v9/iana/etypeID"
	"github.com/jfjallid/gokrb5/v9/iana/patype"
	"github.com/jfjallid/gokrb5/v9/messages"
	"github.com/jfjallid/gokrb5/v9/types"
)

// RequestSalt sends a pre-authentication-less AS-REQ for cname and returns the
// salt the KDC advertises for the account, taken from PA-ETYPE-INFO2 (falling
// back to PA-ETYPE-INFO). The salt is required to derive the correct
// password-based keys for accounts whose salt is not the default
// REALM+sAMAccountName form (renamed accounts, accounts created with an explicit
// salt, some computer accounts).
//
// The salt is only returned by the KDC in the KDC_ERR_PREAUTH_REQUIRED error's
// e-data. ASExchange(Ext) would transparently retry the request with
// pre-authentication and discard that error, so this helper sends the request
// directly via sendToKDC and parses the error itself. No credentials are needed:
// the lookup is an unauthenticated AS-REQ.
func (cl *Client) RequestSalt(cname types.PrincipalName, realm string) (string, error) {
	asReq, err := messages.NewASReqForTGT(realm, cl.Config, cname)
	if err != nil {
		return "", fmt.Errorf("failed to build AS-REQ for salt query: %v", err)
	}
	b, err := asReq.Marshal()
	if err != nil {
		return "", fmt.Errorf("failed to marshal AS-REQ for salt query: %v", err)
	}

	rb, err := cl.sendToKDC(b, realm)
	if err != nil {
		krberr, ok := err.(messages.KRBError)
		if !ok {
			return "", fmt.Errorf("salt query failed: %v", err)
		}
		if krberr.ErrorCode != errorcode.KDC_ERR_PREAUTH_REQUIRED {
			return "", fmt.Errorf("salt query returned unexpected KDC error: %v", krberr)
		}
		var pas types.PADataSequence
		if e := pas.Unmarshal(krberr.EData); e != nil {
			return "", fmt.Errorf("salt query: failed to parse KRBError PAData: %v", e)
		}
		return saltFromPAData(pas)
	}

	// The KDC did not require pre-authentication (e.g. DONT_REQ_PREAUTH); the
	// salt may still be advertised in the AS-REP PAData.
	var asRep messages.ASRep
	if e := asRep.Unmarshal(rb); e != nil {
		return "", fmt.Errorf("salt query: failed to parse AS-REP: %v", e)
	}
	return saltFromPAData(asRep.PAData)
}

// saltFromPAData extracts the account salt from a PADataSequence, preferring an
// AES PA-ETYPE-INFO2 entry, then any non-empty PA-ETYPE-INFO2 salt, then a
// PA-ETYPE-INFO salt.
func saltFromPAData(pas types.PADataSequence) (string, error) {
	var fallback string
	var haveFallback bool
	for _, pa := range pas {
		switch pa.PADataType {
		case patype.PA_ETYPE_INFO2:
			info, err := pa.GetETypeInfo2()
			if err != nil {
				continue
			}
			for _, e := range info {
				if e.Salt == "" {
					continue
				}
				//TODO extend when SHA2 salts are implemented in Active Directory
				if e.EType == etypeID.AES256_CTS_HMAC_SHA1_96 || e.EType == etypeID.AES128_CTS_HMAC_SHA1_96 {
					return e.Salt, nil
				}
				if !haveFallback {
					fallback, haveFallback = e.Salt, true
				}
			}
		case patype.PA_ETYPE_INFO:
			info, err := pa.GetETypeInfo()
			if err != nil {
				continue
			}
			for _, e := range info {
				if len(e.Salt) > 0 && !haveFallback {
					fallback, haveFallback = string(e.Salt), true
				}
			}
		}
	}
	if haveFallback {
		return fallback, nil
	}
	return "", fmt.Errorf("KDC response did not include a salt (no PA-ETYPE-INFO2)")
}
