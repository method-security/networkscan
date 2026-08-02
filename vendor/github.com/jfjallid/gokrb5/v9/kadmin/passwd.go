// Package kadmin provides Kerberos administration capabilities.
package kadmin

import (
	"github.com/jfjallid/gokrb5/v9/crypto"
	"github.com/jfjallid/gokrb5/v9/krberror"
	"github.com/jfjallid/gokrb5/v9/messages"
	"github.com/jfjallid/gokrb5/v9/types"
)

// ChangePasswdMsg generates a change/set password request and also returns the
// key needed to decrypt the reply.
//
// authCName/authRealm identify the authenticated client and MUST match the
// principal the supplied ticket was issued to — they are placed in the AP-REQ
// authenticator, and a mismatch makes the kpasswd server reject the request
// with KRB_AP_ERR_BADMATCH (or, when only the name differs, an access-denied
// result). targName/targRealm identify the account whose password is being set
// and go into the (set-password) ChangePasswdData; for a self password change
// they are the same principal as the authenticated client.
func ChangePasswdMsg(authCName types.PrincipalName, authRealm string, targName types.PrincipalName, targRealm, password string, tkt messages.Ticket, sessionKey types.EncryptionKey) (r Request, k types.EncryptionKey, err error) {
	// Create change password data struct and marshal to bytes
	chgpasswd := ChangePasswdData{
		NewPasswd: []byte(password),
		TargName:  targName,
		TargRealm: targRealm,
	}
	chpwdb, err := chgpasswd.Marshal()
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error marshaling change passwd data")
		return
	}

	// Generate authenticator for the authenticated client (must match the ticket)
	auth, err := types.NewAuthenticator(authRealm, authCName)
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")
		return
	}
	etype, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error generating subkey etype")
		return
	}
	err = auth.GenerateSeqNumberAndSubKey(etype.GetETypeID(), etype.GetKeyByteSize())
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error generating subkey")
		return
	}
	k = auth.SubKey

	// Generate AP_REQ
	APreq, err := messages.NewAPReq(tkt, sessionKey, auth)
	if err != nil {
		return
	}

	// Form the KRBPriv encpart data
	kp := messages.EncKrbPrivPart{
		UserData:       chpwdb,
		Timestamp:      auth.CTime,
		Usec:           auth.Cusec,
		SequenceNumber: auth.SeqNumber,
	}
	kpriv := messages.NewKRBPriv(kp)
	err = kpriv.EncryptEncPart(k)
	if err != nil {
		err = krberror.Errorf(err, krberror.EncryptingError, "error encrypting change passwd data")
		return
	}

	r = Request{
		APREQ:   APreq,
		KRBPriv: kpriv,
	}
	return
}
