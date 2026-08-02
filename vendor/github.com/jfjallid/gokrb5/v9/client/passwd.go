package client

import (
	"fmt"

	"github.com/jfjallid/gokrb5/v9/iana/nametype"
	"github.com/jfjallid/gokrb5/v9/kadmin"
	"github.com/jfjallid/gokrb5/v9/messages"
	"github.com/jfjallid/gokrb5/v9/types"
)

// Kpasswd server response codes.
const (
	KRB5_KPASSWD_SUCCESS             = 0
	KRB5_KPASSWD_MALFORMED           = 1
	KRB5_KPASSWD_HARDERROR           = 2
	KRB5_KPASSWD_AUTHERROR           = 3
	KRB5_KPASSWD_SOFTERROR           = 4
	KRB5_KPASSWD_ACCESSDENIED        = 5
	KRB5_KPASSWD_BAD_VERSION         = 6
	KRB5_KPASSWD_INITIAL_FLAG_NEEDED = 7
)

// ChangePasswd changes the password of the client to the value provided.
func (cl *Client) ChangePasswd(newPasswd string) (bool, error) {
	ASReq, err := messages.NewASReqForChgPasswd(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		return false, err
	}
	ASRep, err := cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
	if err != nil {
		return false, err
	}

	// Self change: omit the target name/realm entirely. A kpasswd request that
	// carries a target is an administrative *set* (reset) and is authorized
	// against the "Reset Password" right, which an account does not hold over
	// itself — including it makes the KDC answer ACCESSDENIED. With no target
	// the request is a self-service *change*, authorized by the initial ticket
	// alone. The authenticator still uses the realm the KDC put in the ticket so
	// a NetBIOS-form login produces an authenticator that matches the ticket.
	msg, key, err := kadmin.ChangePasswdMsg(cl.Credentials.CName(), ASRep.Ticket.Realm, types.PrincipalName{}, "", newPasswd, ASRep.Ticket, ASRep.DecryptedEncPart.Key)
	if err != nil {
		return false, err
	}
	r, err := cl.sendToKPasswd(msg)
	if err != nil {
		return false, err
	}
	err = r.Decrypt(key)
	if err != nil {
		return false, err
	}
	if r.ResultCode != KRB5_KPASSWD_SUCCESS {
		return false, fmt.Errorf("error response from kadmin: code: %d; result: %s; krberror: %v", r.ResultCode, r.Result, r.KRBError)
	}
	cl.Credentials.WithPassword(newPasswd)
	return true, nil
}

// SetPasswd resets the password of the target principal in targetRealm using the
// client's existing TGT. Unlike ChangePasswd (which authenticates as the account
// whose password is being changed via an AS-REQ to kadmin/changepw), this obtains
// a service ticket for kadmin/changepw and names the target in the request, so the
// caller must hold reset privileges over the target account.
func (cl *Client) SetPasswd(targetUser, targetRealm, newPasswd string) (bool, error) {
	tkt, key, err := cl.GetServiceTicketExt("kadmin/changepw", cl.Credentials.Domain())
	if err != nil {
		return false, err
	}
	targName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, targetUser)
	// The authenticator must identify the authenticated client (the admin who
	// holds the kadmin/changepw ticket), not the target account; the target only
	// goes into the ChangePasswdData. Use the ticket's realm for the
	// authenticator and the canonical form of the target realm so a NetBIOS-form
	// realm doesn't cause a KRB_AP_ERR_BADMATCH / access-denied at the server.
	msg, k, err := kadmin.ChangePasswdMsg(cl.Credentials.CName(), tkt.Realm, targName, cl.RealmAliases().Resolve(targetRealm), newPasswd, tkt, key)
	if err != nil {
		return false, err
	}
	r, err := cl.sendToKPasswd(msg)
	if err != nil {
		return false, err
	}
	err = r.Decrypt(k)
	if err != nil {
		return false, err
	}
	if r.ResultCode != KRB5_KPASSWD_SUCCESS {
		return false, fmt.Errorf("error response from kadmin: code: %d; result: %s; krberror: %v", r.ResultCode, r.Result, r.KRBError)
	}
	return true, nil
}

func (cl *Client) sendToKPasswd(msg kadmin.Request) (r kadmin.Reply, err error) {
	_, kps, err := cl.Config.GetKpasswdServers(cl.Credentials.Domain(), true)
	if err != nil {
		return
	}
	b, err := msg.Marshal()
	if err != nil {
		return
	}
	var rb []byte
	if len(b) <= cl.Config.LibDefaults.UDPPreferenceLimit {
		rb, err = dialSendUDP(kps, b, cl.settings.GetDialTimeout())
		if err != nil {
			return
		}
	} else {
		rb, err = dialSendTCP(kps, b, cl.settings.GetDialTimeout(), cl.settings.ProxyDialer())
		if err != nil {
			return
		}
	}
	err = r.Unmarshal(rb)
	return
}
