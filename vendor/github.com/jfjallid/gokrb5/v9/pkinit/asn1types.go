// Package pkinit implements PKINIT (RFC 4556) for Kerberos authentication
// using X.509 certificates with Diffie-Hellman key agreement.
package pkinit

import (
	"encoding/asn1"
	"math/big"
	"time"
)

// OID constants for PKINIT and CMS
var (
	OIDSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDData              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDPKINITAuthData    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1}    // id-pkinit-authData
	OIDPKINITDHKeyData   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 2}    // id-pkinit-DHKeyData
	OIDDiffieHellman     = asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}     // dhpublicnumber
	OIDSHA1              = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}         // id-sha1
	OIDSHA1WithRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5} // sha1WithRSAEncryption
	OIDRSAEncryption     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDContentType       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDMSKDCNegoToken    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 5}    // id-pkinit-ms-san (not always needed)
)

// PKAuthenticator - RFC 4556 Section 3.2.1
type PKAuthenticator struct {
	CUSec      int       `asn1:"explicit,tag:0"`
	CTime      time.Time `asn1:"generalized,explicit,tag:1"`
	Nonce      int       `asn1:"explicit,tag:2"`
	PAChecksum []byte    `asn1:"explicit,optional,tag:3"`
}

// AuthPack - RFC 4556 Section 3.2.1
type AuthPack struct {
	PKAuthenticator   PKAuthenticator      `asn1:"explicit,tag:0"`
	ClientPublicValue SubjectPublicKeyInfo `asn1:"explicit,optional,tag:1"`
	ClientDHNonce     []byte               `asn1:"explicit,optional,tag:3"`
}

// SubjectPublicKeyInfo for DH public key
type SubjectPublicKeyInfo struct {
	Algorithm AlgorithmIdentifier
	PublicKey asn1.BitString
}

// AlgorithmIdentifier per X.509
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// DomainParameters for DH - RFC 3279 Section 2.3.3
type DomainParameters struct {
	P *big.Int
	G *big.Int
	Q *big.Int `asn1:"optional"`
}

// ExternalPrincipalIdentifier - RFC 4556 Section 3.2.1
type ExternalPrincipalIdentifier struct {
	SubjectName         []byte `asn1:"implicit,optional,tag:0"`
	IssuerAndSerial     []byte `asn1:"implicit,optional,tag:1"`
	SubjectKeyIdentifier []byte `asn1:"implicit,optional,tag:2"`
}

// PAPKASReq - RFC 4556 Section 3.2.1 (PA-PK-AS-REQ)
type PAPKASReq struct {
	SignedAuthPack    []byte                        `asn1:"implicit,tag:0"`
	TrustedCertifiers []ExternalPrincipalIdentifier `asn1:"explicit,optional,tag:1"`
	KDCPkId           []byte                        `asn1:"implicit,optional,tag:2"`
}

// PAPKASRep - RFC 4556 Section 3.2.3 (PA-PK-AS-REP)
type PAPKASRep struct {
	DHInfo     DHRepInfo `asn1:"explicit,optional,tag:0"`
	EncKeyPack []byte    `asn1:"implicit,optional,tag:1"`
}

// DHRepInfo - RFC 4556 Section 3.2.3.1
type DHRepInfo struct {
	DHSignedData  []byte `asn1:"implicit,tag:0"`
	ServerDHNonce []byte `asn1:"explicit,optional,tag:1"`
}

// KDCDHKeyInfo - RFC 4556 Section 3.2.3.1
type KDCDHKeyInfo struct {
	SubjectPublicKey asn1.BitString `asn1:"explicit,tag:0"`
	Nonce            int            `asn1:"explicit,tag:1"`
	DHKeyExpiration  asn1.RawValue  `asn1:"explicit,optional,tag:2"`
}

// --- CMS (RFC 5652) types ---

// ContentInfo is the top-level CMS structure
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// SignedData per RFC 5652 Section 5.1
type SignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue `asn1:"set"` // SET OF AlgorithmIdentifier
	EncapContentInfo EncapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,implicit,tag:0"`
	SignerInfos      asn1.RawValue `asn1:"set"` // SET OF SignerInfo
}

// EncapsulatedContentInfo per RFC 5652
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// SignerInfo per RFC 5652
type SignerInfo struct {
	Version            int
	SID                IssuerAndSerialNumber
	DigestAlgorithm    AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,implicit,tag:0"`
	SignatureAlgorithm AlgorithmIdentifier
	Signature          []byte
}

// IssuerAndSerialNumber identifies the signer's certificate
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// Attribute per RFC 5652 (used in SignedAttrs)
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// --- Parsed CMS types for response processing ---

// ParsedContentInfo for unmarshaling CMS responses
type ParsedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// ParsedSignedData for unmarshaling CMS SignedData responses
type ParsedSignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue    `asn1:"set"`
	EncapContentInfo asn1.RawValue    ``
	Certificates     asn1.RawValue    `asn1:"optional,implicit,tag:0"`
	CRLs             asn1.RawValue    `asn1:"optional,implicit,tag:1"`
	SignerInfos      asn1.RawValue    `asn1:"set"`
}

// ParsedEncapsulatedContentInfo for response parsing
type ParsedEncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}
