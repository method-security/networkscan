// Package sasl provides SASL authentication mechanism selection and parsing utilities.
package sasl

import (
	"strings"
)

// Mechanism represents a SASL authentication mechanism.
type Mechanism string

const (
	MechanismPlain   Mechanism = "PLAIN"
	MechanismLogin   Mechanism = "LOGIN"
	MechanismCramMD5 Mechanism = "CRAM-MD5"
	MechanismGSSAPI  Mechanism = "GSSAPI"
	MechanismXOAuth2 Mechanism = "XOAUTH2"
)

// MechanismPrecedence lists mechanisms from strongest to weakest for auto-selection.
var MechanismPrecedence = []Mechanism{
	MechanismGSSAPI,
	MechanismXOAuth2,
	MechanismCramMD5,
	MechanismPlain,
	MechanismLogin,
}

// SelectStrongest returns the strongest available mechanism from the advertised list,
// filtered by allowPlain (if false, PLAIN and LOGIN are excluded unless no other option).
func SelectStrongest(available []Mechanism, allowPlain bool) (Mechanism, bool) {
	availableSet := make(map[Mechanism]bool)
	for _, m := range available {
		availableSet[m] = true
	}
	for _, candidate := range MechanismPrecedence {
		if !allowPlain && (candidate == MechanismPlain || candidate == MechanismLogin) {
			continue
		}
		if availableSet[candidate] {
			return candidate, true
		}
	}
	// Fallback: if allowPlain, try PLAIN/LOGIN
	if !allowPlain {
		return "", false
	}
	for _, candidate := range []Mechanism{MechanismPlain, MechanismLogin} {
		if availableSet[candidate] {
			return candidate, true
		}
	}
	return "", false
}

// ParseMechanisms parses the SASL mechanisms from an IMAP CAPABILITY response.
// It looks for capability tokens of the form "AUTH=<MECHANISM>" (case-insensitive,
// per RFC 3501 §2.6 which states capability names are not case-sensitive).
func ParseMechanisms(capabilities []string) []Mechanism {
	var mechs []Mechanism
	for _, cap := range capabilities {
		upper := strings.ToUpper(cap)
		if strings.HasPrefix(upper, "AUTH=") {
			mech := Mechanism(strings.TrimPrefix(upper, "AUTH="))
			mechs = append(mechs, mech)
		}
	}
	return mechs
}
