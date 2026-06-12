package kerberos

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jfjallid/gokrb5/v8/messages"
)

// Hashcat mode constants for each (operation, etype) pair. Hashcat doesn't
// have a single "kerberoast" or "AS-REP roast" mode — the mode is selected
// by both the attack and the ticket's encryption type, and a mismatched
// mode is silently uncrackable.
//
// Reference: https://hashcat.net/wiki/doku.php?id=example_hashes
const (
	// AS-REP roast (krb5asrep). Hashcat ships only an RC4 mode for AS-REP;
	// AES AS-REP roast is not directly supported.
	HashcatModeASRepRoastRC4 = 18200

	// Kerberoast (krb5tgs) per ticket etype.
	HashcatModeKerberoastRC4    = 13100 // etype 23
	HashcatModeKerberoastAES128 = 19600 // etype 17
	HashcatModeKerberoastAES256 = 19700 // etype 18
)

// gokrb5 etype IDs (mirrors iana/etypeID values 17/18/23 inline so this
// file doesn't pick up another dependency on the iana subtree).
const (
	etypeAES128CTSHMACSHA196 int32 = 17
	etypeAES256CTSHMACSHA196 int32 = 18
	etypeRC4HMAC             int32 = 23
)

// HashcatModeForASRep returns the hashcat mode for an AS-REP roast hash of
// the given etype, or (0, false) if hashcat doesn't have a mode for it.
// Only RC4 is supported for AS-REP roast.
func HashcatModeForASRep(etype int32) (int, bool) {
	if etype == etypeRC4HMAC {
		return HashcatModeASRepRoastRC4, true
	}
	return 0, false
}

// HashcatModeForTGSRep returns the hashcat mode for a kerberoast hash of
// the given TGS ticket etype, or (0, false) if hashcat doesn't have a mode
// for it.
func HashcatModeForTGSRep(etype int32) (int, bool) {
	switch etype {
	case etypeRC4HMAC:
		return HashcatModeKerberoastRC4, true
	case etypeAES128CTSHMACSHA196:
		return HashcatModeKerberoastAES128, true
	case etypeAES256CTSHMACSHA196:
		return HashcatModeKerberoastAES256, true
	}
	return 0, false
}

// FormatASRepHashcat formats an AS-REP response in hashcat $krb5asrep$ format.
// Returns empty string if the cipher is too short to format (< 16 bytes) or
// if hashcat doesn't have a mode for the etype (it's RC4-only). Format
// reference: hashcat example_hashes.txt mode 18200.
func FormatASRepHashcat(asrep messages.ASRep) string {
	cipher := asrep.EncPart.Cipher
	if len(cipher) < 16 {
		return ""
	}
	if _, ok := HashcatModeForASRep(asrep.EncPart.EType); !ok {
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

// FormatTGSRepHashcat formats a TGS-REP in hashcat $krb5tgs$ format. Returns
// empty string if the ticket cipher is too short or if the etype isn't a
// known kerberoast etype. RC4 uses asterisk-delimited segments
// (mode 13100); AES uses a single cipher blob without asterisks
// (modes 19600/19700). Format references: hashcat example_hashes.txt.
func FormatTGSRepHashcat(rep messages.TGSRep, username string) string {
	cipher := rep.Ticket.EncPart.Cipher
	etype := rep.Ticket.EncPart.EType
	if len(cipher) < 16 {
		return ""
	}
	spn := strings.Join(rep.Ticket.SName.NameString, "/")
	switch etype {
	case etypeRC4HMAC:
		// 13100 layout: $krb5tgs$23$*<user>$<realm>$<spn>*$<checksum[:16]>$<edata[16:]>
		return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
			etype,
			username,
			rep.Ticket.Realm,
			spn,
			hex.EncodeToString(cipher[:16]),
			hex.EncodeToString(cipher[16:]))
	case etypeAES128CTSHMACSHA196, etypeAES256CTSHMACSHA196:
		// 19600 / 19700 layout: $krb5tgs$<etype>$<user>$<realm>$<spn>$<cipher>
		// (single blob, no asterisks — the AES HMAC is part of the cipher tail).
		return fmt.Sprintf("$krb5tgs$%d$%s$%s$%s$%s",
			etype,
			username,
			rep.Ticket.Realm,
			spn,
			hex.EncodeToString(cipher))
	}
	return ""
}
