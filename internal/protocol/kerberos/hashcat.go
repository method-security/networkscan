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
// known kerberoast etype.
//
// Layouts (cross-checked against impacket GetUserSPNs.py and Rubeus):
//   - RC4 (13100): $krb5tgs$23$*<svcName>$<realm>$<spn>*$<checksum[:16]>$<edata[16:]>
//     checksum is the FIRST 16 bytes (RFC 4757 layout).
//   - AES128 (19600) / AES256 (19700): $krb5tgs$<etype>$<svcName>$<realm>$*<spn>*$<HMAC[-12:]>$<edata[:-12]>
//     HMAC-SHA1-96 is the LAST 12 bytes (RFC 3962 layout). The asterisks
//     wrap the SPN — both impacket and Rubeus emit this shape and hashcat
//     parses it.
//
// The <svcName> field is the SPN extracted from the ticket's SName (the service
// account identifier as presented to hashcat). For AES modes the name is part
// of the key derivation salt, so it MUST identify the service account, not the
// authenticating user. When the SAM account name is not independently known
// (i.e. we obtained the TGS-REP without LDAP enumeration), embedding the SPN
// itself is the correct fallback — this is the same behaviour as impacket
// GetUserSPNs.py and Rubeus when no account mapping is available.
//
// The earlier "AES is one blob with no asterisks" layout that lived here
// loaded into hashcat as garbage; AES kerberoasts looked successful in the
// report but never cracked. Spotted by Bugbot round-8.
func FormatTGSRepHashcat(rep messages.TGSRep) string {
	cipher := rep.Ticket.EncPart.Cipher
	etype := rep.Ticket.EncPart.EType
	spn := strings.Join(rep.Ticket.SName.NameString, "/")
	// Use the SPN as the service-account identifier. When the SAM account name
	// is unknown (our typical case — no LDAP lookup performed), the SPN is the
	// authoritative account handle. This matches impacket / Rubeus behaviour.
	svcName := spn
	switch etype {
	case etypeRC4HMAC:
		if len(cipher) < 16 {
			return ""
		}
		return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
			etype,
			svcName,
			rep.Ticket.Realm,
			spn,
			hex.EncodeToString(cipher[:16]),
			hex.EncodeToString(cipher[16:]))
	case etypeAES128CTSHMACSHA196, etypeAES256CTSHMACSHA196:
		// AES HMAC-SHA1-96 is the trailing 12 bytes; everything before is
		// the confounder + encrypted ticket body.
		if len(cipher) < 12 {
			return ""
		}
		hmac := cipher[len(cipher)-12:]
		edata := cipher[:len(cipher)-12]
		return fmt.Sprintf("$krb5tgs$%d$%s$%s$*%s*$%s$%s",
			etype,
			svcName,
			rep.Ticket.Realm,
			spn,
			hex.EncodeToString(hmac),
			hex.EncodeToString(edata))
	}
	return ""
}
