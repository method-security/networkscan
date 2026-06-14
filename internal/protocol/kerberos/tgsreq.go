package kerberos

import (
	"fmt"
	"strings"

	"github.com/jfjallid/gokrb5/v8/config"
	"github.com/jfjallid/gokrb5/v8/iana/nametype"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/types"
)

// BuildTGSReqFromTGT builds a TGS-REQ using an existing TGT for the specified SPN.
func BuildTGSReqFromTGT(tgt messages.Ticket, sessionKey types.EncryptionKey, cname types.PrincipalName, realm, spn string, cfg *config.Config) (messages.TGSReq, error) {
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, spn)

	tgsReq, err := messages.NewTGSReq(cname, strings.ToUpper(realm), strings.ToUpper(realm), cfg, tgt, sessionKey, sname, false)
	if err != nil {
		return messages.TGSReq{}, fmt.Errorf("failed to create TGS-REQ: %w", err)
	}

	return tgsReq, nil
}

// ExtractTicketCipher extracts the encryption type and cipher from a TGS-REP for hashcat formatting.
func ExtractTicketCipher(rep messages.TGSRep) (etype int32, cipher []byte) {
	return rep.Ticket.EncPart.EType, rep.Ticket.EncPart.Cipher
}
