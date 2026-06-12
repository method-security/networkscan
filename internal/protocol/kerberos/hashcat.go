package kerberos

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jfjallid/gokrb5/v8/messages"
)

const (
	// HashcatModeASRepRoast is the hashcat mode for AS-REP roasting (krb5asrep).
	HashcatModeASRepRoast = 18200
	// HashcatModeKerberoast is the hashcat mode for Kerberoasting (krb5tgs).
	HashcatModeKerberoast = 13100
)

// FormatASRepHashcat formats an AS-REP response in hashcat $krb5asrep$ format.
// Returns empty string if the cipher is too short to format (< 16 bytes).
func FormatASRepHashcat(asrep messages.ASRep) string {
	cipher := asrep.EncPart.Cipher
	if len(cipher) < 16 {
		return ""
	}
	username := strings.Join(asrep.CName.NameString, "/")
	return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s$%s",
		asrep.EncPart.EType,
		username,
		asrep.CRealm,
		hex.EncodeToString(cipher[:16]),
		hex.EncodeToString(cipher[16:]))
}

// FormatTGSRepHashcat formats a TGS-REP in hashcat $krb5tgs$ format.
// Returns empty string if the ticket cipher is too short to format (< 16 bytes).
func FormatTGSRepHashcat(rep messages.TGSRep, username string) string {
	cipher := rep.Ticket.EncPart.Cipher
	if len(cipher) < 16 {
		return ""
	}
	return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
		rep.Ticket.EncPart.EType,
		username,
		rep.Ticket.Realm,
		strings.Join(rep.Ticket.SName.NameString, "/"),
		hex.EncodeToString(cipher[:16]),
		hex.EncodeToString(cipher[16:]))
}
