package ike

import (
	"strings"

	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
)

func ToFernEncryptionAlgorithm(name string) (commonprotocolfern.IkeEncryptionAlgorithm, bool) {
	switch name {
	case "DES-IV64":
		return commonprotocolfern.IkeEncryptionAlgorithmDesIv64, true
	case "DES":
		return commonprotocolfern.IkeEncryptionAlgorithmDes, true
	case "DES-CBC":
		return commonprotocolfern.IkeEncryptionAlgorithmDesCbc, true
	case "3DES-CBC":
		return commonprotocolfern.IkeEncryptionAlgorithmThreeDesCbc, true
	case "IDEA-CBC":
		return commonprotocolfern.IkeEncryptionAlgorithmIdeaCbc, true
	case "CAST-CBC":
		return commonprotocolfern.IkeEncryptionAlgorithmCastCbc, true
	case "Blowfish-CBC":
		return commonprotocolfern.IkeEncryptionAlgorithmBlowfishCbc, true
	case "NULL":
		return commonprotocolfern.IkeEncryptionAlgorithmNull, true
	case "AES-CBC":
		return commonprotocolfern.IkeEncryptionAlgorithmAesCbc, true
	case "AES-CTR":
		return commonprotocolfern.IkeEncryptionAlgorithmAesCtr, true
	case "AES-GCM-8":
		return commonprotocolfern.IkeEncryptionAlgorithmAesGcm8, true
	case "AES-GCM-12":
		return commonprotocolfern.IkeEncryptionAlgorithmAesGcm12, true
	case "AES-GCM-16":
		return commonprotocolfern.IkeEncryptionAlgorithmAesGcm16, true
	case "Camellia-CBC":
		return commonprotocolfern.IkeEncryptionAlgorithmCamelliaCbc, true
	case "ChaCha20-Poly1305":
		return commonprotocolfern.IkeEncryptionAlgorithmChacha20Poly1305, true
	}
	return "", false
}

func ToFernHashAlgorithm(name string) (commonprotocolfern.IkeHashAlgorithm, bool) {
	switch name {
	case "PRF-HMAC-MD5":
		return commonprotocolfern.IkeHashAlgorithmPrfHmacMd5, true
	case "PRF-HMAC-SHA1":
		return commonprotocolfern.IkeHashAlgorithmPrfHmacSha1, true
	case "PRF-HMAC-TIGER":
		return commonprotocolfern.IkeHashAlgorithmPrfHmacTiger, true
	case "PRF-AES128-XCBC":
		return commonprotocolfern.IkeHashAlgorithmPrfAes128Xcbc, true
	case "PRF-HMAC-SHA256":
		return commonprotocolfern.IkeHashAlgorithmPrfHmacSha256, true
	case "PRF-HMAC-SHA384":
		return commonprotocolfern.IkeHashAlgorithmPrfHmacSha384, true
	case "PRF-HMAC-SHA512":
		return commonprotocolfern.IkeHashAlgorithmPrfHmacSha512, true
	case "PRF-AES128-CMAC":
		return commonprotocolfern.IkeHashAlgorithmPrfAes128Cmac, true
	case "NONE":
		return commonprotocolfern.IkeHashAlgorithmNone, true
	case "HMAC-MD5-96":
		return commonprotocolfern.IkeHashAlgorithmHmacMd596, true
	case "HMAC-SHA1-96":
		return commonprotocolfern.IkeHashAlgorithmHmacSha196, true
	case "DES-MAC":
		return commonprotocolfern.IkeHashAlgorithmDesMac, true
	case "KPDK-MD5":
		return commonprotocolfern.IkeHashAlgorithmKpdkMd5, true
	case "AES-XCBC-96":
		return commonprotocolfern.IkeHashAlgorithmAesXcbc96, true
	case "HMAC-MD5-128":
		return commonprotocolfern.IkeHashAlgorithmHmacMd5128, true
	case "HMAC-SHA1-160":
		return commonprotocolfern.IkeHashAlgorithmHmacSha1160, true
	case "AES-CMAC-96":
		return commonprotocolfern.IkeHashAlgorithmAesCmac96, true
	case "AES-128-GMAC":
		return commonprotocolfern.IkeHashAlgorithmAes128Gmac, true
	case "AES-192-GMAC":
		return commonprotocolfern.IkeHashAlgorithmAes192Gmac, true
	case "AES-256-GMAC":
		return commonprotocolfern.IkeHashAlgorithmAes256Gmac, true
	case "HMAC-SHA256-128":
		return commonprotocolfern.IkeHashAlgorithmHmacSha256128, true
	case "HMAC-SHA384-192":
		return commonprotocolfern.IkeHashAlgorithmHmacSha384192, true
	case "HMAC-SHA512-256":
		return commonprotocolfern.IkeHashAlgorithmHmacSha512256, true
	case "MD5":
		return commonprotocolfern.IkeHashAlgorithmMd5, true
	case "SHA1":
		return commonprotocolfern.IkeHashAlgorithmSha1, true
	case "SHA256":
		return commonprotocolfern.IkeHashAlgorithmSha256, true
	case "SHA384":
		return commonprotocolfern.IkeHashAlgorithmSha384, true
	case "SHA512":
		return commonprotocolfern.IkeHashAlgorithmSha512, true
	}
	return "", false
}

func ToFernAuthenticationMethod(name string) (commonprotocolfern.IkeAuthenticationMethod, bool) {
	switch name {
	case "PSK":
		return commonprotocolfern.IkeAuthenticationMethodPsk, true
	case "RSA_SIGNATURE":
		return commonprotocolfern.IkeAuthenticationMethodRsaSignature, true
	case "DSS_SIGNATURE":
		return commonprotocolfern.IkeAuthenticationMethodDssSignature, true
	case "ECDSA_SHA256_P256":
		return commonprotocolfern.IkeAuthenticationMethodEcdsaSha256P256, true
	case "ECDSA_SHA384_P384":
		return commonprotocolfern.IkeAuthenticationMethodEcdsaSha384P384, true
	case "ECDSA_SHA512_P521":
		return commonprotocolfern.IkeAuthenticationMethodEcdsaSha512P521, true
	}
	return "", false
}

func ToFernDHGroup(name string) (commonprotocolfern.IkeDhGroup, bool) {
	switch name {
	case "MODP-768":
		return commonprotocolfern.IkeDhGroupModp768, true
	case "MODP-1024":
		return commonprotocolfern.IkeDhGroupModp1024, true
	case "MODP-1536":
		return commonprotocolfern.IkeDhGroupModp1536, true
	case "MODP-2048":
		return commonprotocolfern.IkeDhGroupModp2048, true
	case "MODP-3072":
		return commonprotocolfern.IkeDhGroupModp3072, true
	case "MODP-4096":
		return commonprotocolfern.IkeDhGroupModp4096, true
	case "MODP-6144":
		return commonprotocolfern.IkeDhGroupModp6144, true
	case "MODP-8192":
		return commonprotocolfern.IkeDhGroupModp8192, true
	case "MODP-1024-160":
		return commonprotocolfern.IkeDhGroupModp1024160, true
	case "MODP-2048-224":
		return commonprotocolfern.IkeDhGroupModp2048224, true
	case "MODP-2048-256":
		return commonprotocolfern.IkeDhGroupModp2048256, true
	case "ECP-192":
		return commonprotocolfern.IkeDhGroupEcp192, true
	case "ECP-224":
		return commonprotocolfern.IkeDhGroupEcp224, true
	case "ECP-256":
		return commonprotocolfern.IkeDhGroupEcp256, true
	case "ECP-384":
		return commonprotocolfern.IkeDhGroupEcp384, true
	case "ECP-521":
		return commonprotocolfern.IkeDhGroupEcp521, true
	case "ECP-224-BP":
		return commonprotocolfern.IkeDhGroupEcp224Bp, true
	case "ECP-256-BP":
		return commonprotocolfern.IkeDhGroupEcp256Bp, true
	case "ECP-384-BP":
		return commonprotocolfern.IkeDhGroupEcp384Bp, true
	case "ECP-512-BP":
		return commonprotocolfern.IkeDhGroupEcp512Bp, true
	case "Curve25519":
		return commonprotocolfern.IkeDhGroupCurve25519, true
	case "Curve448":
		return commonprotocolfern.IkeDhGroupCurve448, true
	}
	return "", false
}

func MergeFernEncryptionAlgorithms(existing []commonprotocolfern.IkeEncryptionAlgorithm, names []string) []commonprotocolfern.IkeEncryptionAlgorithm {
	for _, name := range names {
		if mapped, ok := ToFernEncryptionAlgorithm(name); ok {
			existing = appendUniqueTyped(existing, mapped)
		}
	}
	return existing
}

func MergeFernHashAlgorithms(existing []commonprotocolfern.IkeHashAlgorithm, names []string) []commonprotocolfern.IkeHashAlgorithm {
	for _, name := range names {
		if mapped, ok := ToFernHashAlgorithm(name); ok {
			existing = appendUniqueTyped(existing, mapped)
		}
	}
	return existing
}

func MergeFernAuthenticationMethods(existing []commonprotocolfern.IkeAuthenticationMethod, names []string) []commonprotocolfern.IkeAuthenticationMethod {
	for _, name := range names {
		if mapped, ok := ToFernAuthenticationMethod(name); ok {
			existing = appendUniqueTyped(existing, mapped)
		}
	}
	return existing
}

func MergeFernDHGroups(existing []commonprotocolfern.IkeDhGroup, names []string) []commonprotocolfern.IkeDhGroup {
	for _, name := range names {
		if mapped, ok := ToFernDHGroup(name); ok {
			existing = appendUniqueTyped(existing, mapped)
		}
	}
	return existing
}

func appendUniqueTyped[T comparable](slice []T, item T) []T {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

// EncryptionAlgorithmToString converts a Fern IkeEncryptionAlgorithm to its
// protocol-friendly display name (e.g., "3DES-CBC" not "THREE_DES_CBC").
func EncryptionAlgorithmToString(e commonprotocolfern.IkeEncryptionAlgorithm) string {
	switch e {
	case commonprotocolfern.IkeEncryptionAlgorithmThreeDesCbc:
		return "3DES-CBC"
	case commonprotocolfern.IkeEncryptionAlgorithmBlowfishCbc:
		return "Blowfish-CBC"
	case commonprotocolfern.IkeEncryptionAlgorithmCamelliaCbc:
		return "Camellia-CBC"
	case commonprotocolfern.IkeEncryptionAlgorithmChacha20Poly1305:
		return "ChaCha20-Poly1305"
	}
	return strings.ReplaceAll(string(e), "_", "-")
}

// HashAlgorithmToString converts a Fern IkeHashAlgorithm to its protocol display name.
func HashAlgorithmToString(h commonprotocolfern.IkeHashAlgorithm) string {
	return strings.ReplaceAll(string(h), "_", "-")
}

// DHGroupToString converts a Fern IkeDhGroup to its protocol display name.
func DHGroupToString(g commonprotocolfern.IkeDhGroup) string {
	switch g {
	case commonprotocolfern.IkeDhGroupCurve25519:
		return "Curve25519"
	case commonprotocolfern.IkeDhGroupCurve448:
		return "Curve448"
	}
	return strings.ReplaceAll(string(g), "_", "-")
}

// AuthMethodToString converts a Fern IkeAuthenticationMethod to its protocol display name.
// Auth method names use underscores (e.g., "RSA_SIGNATURE") to match ToFernAuthenticationMethod
// input strings and the rest of the IKE parsing stack.
func AuthMethodToString(a commonprotocolfern.IkeAuthenticationMethod) string {
	return string(a)
}
