package ike

import (
	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
)

func ToFernEncryptionAlgorithm(name string) commonprotocolfern.IkeEncryptionAlgorithm {
	switch name {
	case "DES-IV64":
		return commonprotocolfern.IkeEncryptionAlgorithmDesIv64
	case "DES":
		return commonprotocolfern.IkeEncryptionAlgorithmDes
	case "DES-CBC":
		return commonprotocolfern.IkeEncryptionAlgorithmDesCbc
	case "3DES-CBC":
		return commonprotocolfern.IkeEncryptionAlgorithmThreeDesCbc
	case "IDEA-CBC":
		return commonprotocolfern.IkeEncryptionAlgorithmIdeaCbc
	case "CAST-CBC":
		return commonprotocolfern.IkeEncryptionAlgorithmCastCbc
	case "Blowfish-CBC":
		return commonprotocolfern.IkeEncryptionAlgorithmBlowfishCbc
	case "NULL":
		return commonprotocolfern.IkeEncryptionAlgorithmNull
	case "AES-CBC":
		return commonprotocolfern.IkeEncryptionAlgorithmAesCbc
	case "AES-CTR":
		return commonprotocolfern.IkeEncryptionAlgorithmAesCtr
	case "AES-GCM-8":
		return commonprotocolfern.IkeEncryptionAlgorithmAesGcm8
	case "AES-GCM-12":
		return commonprotocolfern.IkeEncryptionAlgorithmAesGcm12
	case "AES-GCM-16":
		return commonprotocolfern.IkeEncryptionAlgorithmAesGcm16
	case "Camellia-CBC":
		return commonprotocolfern.IkeEncryptionAlgorithmCamelliaCbc
	case "ChaCha20-Poly1305":
		return commonprotocolfern.IkeEncryptionAlgorithmChacha20Poly1305
	}
	if alg, err := commonprotocolfern.NewIkeEncryptionAlgorithmFromString(name); err == nil {
		return alg
	}
	return commonprotocolfern.IkeEncryptionAlgorithmUnknown
}

func ToFernHashAlgorithm(name string) commonprotocolfern.IkeHashAlgorithm {
	switch name {
	case "PRF-HMAC-MD5":
		return commonprotocolfern.IkeHashAlgorithmPrfHmacMd5
	case "PRF-HMAC-SHA1":
		return commonprotocolfern.IkeHashAlgorithmPrfHmacSha1
	case "PRF-HMAC-TIGER":
		return commonprotocolfern.IkeHashAlgorithmPrfHmacTiger
	case "PRF-AES128-XCBC":
		return commonprotocolfern.IkeHashAlgorithmPrfAes128Xcbc
	case "PRF-HMAC-SHA256":
		return commonprotocolfern.IkeHashAlgorithmPrfHmacSha256
	case "PRF-HMAC-SHA384":
		return commonprotocolfern.IkeHashAlgorithmPrfHmacSha384
	case "PRF-HMAC-SHA512":
		return commonprotocolfern.IkeHashAlgorithmPrfHmacSha512
	case "PRF-AES128-CMAC":
		return commonprotocolfern.IkeHashAlgorithmPrfAes128Cmac
	case "NONE":
		return commonprotocolfern.IkeHashAlgorithmNone
	case "HMAC-MD5-96":
		return commonprotocolfern.IkeHashAlgorithmHmacMd596
	case "HMAC-SHA1-96":
		return commonprotocolfern.IkeHashAlgorithmHmacSha196
	case "DES-MAC":
		return commonprotocolfern.IkeHashAlgorithmDesMac
	case "KPDK-MD5":
		return commonprotocolfern.IkeHashAlgorithmKpdkMd5
	case "AES-XCBC-96":
		return commonprotocolfern.IkeHashAlgorithmAesXcbc96
	case "HMAC-MD5-128":
		return commonprotocolfern.IkeHashAlgorithmHmacMd5128
	case "HMAC-SHA1-160":
		return commonprotocolfern.IkeHashAlgorithmHmacSha1160
	case "AES-CMAC-96":
		return commonprotocolfern.IkeHashAlgorithmAesCmac96
	case "AES-128-GMAC":
		return commonprotocolfern.IkeHashAlgorithmAes128Gmac
	case "AES-192-GMAC":
		return commonprotocolfern.IkeHashAlgorithmAes192Gmac
	case "AES-256-GMAC":
		return commonprotocolfern.IkeHashAlgorithmAes256Gmac
	case "HMAC-SHA256-128":
		return commonprotocolfern.IkeHashAlgorithmHmacSha256128
	case "HMAC-SHA384-192":
		return commonprotocolfern.IkeHashAlgorithmHmacSha384192
	case "HMAC-SHA512-256":
		return commonprotocolfern.IkeHashAlgorithmHmacSha512256
	case "MD5":
		return commonprotocolfern.IkeHashAlgorithmMd5
	case "SHA1":
		return commonprotocolfern.IkeHashAlgorithmSha1
	case "SHA256":
		return commonprotocolfern.IkeHashAlgorithmSha256
	case "SHA384":
		return commonprotocolfern.IkeHashAlgorithmSha384
	case "SHA512":
		return commonprotocolfern.IkeHashAlgorithmSha512
	}
	if alg, err := commonprotocolfern.NewIkeHashAlgorithmFromString(name); err == nil {
		return alg
	}
	return commonprotocolfern.IkeHashAlgorithmUnknown
}

func ToFernAuthenticationMethod(name string) commonprotocolfern.IkeAuthenticationMethod {
	switch name {
	case "PSK":
		return commonprotocolfern.IkeAuthenticationMethodPsk
	case "RSA_SIGNATURE":
		return commonprotocolfern.IkeAuthenticationMethodRsaSignature
	case "DSS_SIGNATURE":
		return commonprotocolfern.IkeAuthenticationMethodDssSignature
	case "ECDSA_SHA256_P256":
		return commonprotocolfern.IkeAuthenticationMethodEcdsaSha256P256
	case "ECDSA_SHA384_P384":
		return commonprotocolfern.IkeAuthenticationMethodEcdsaSha384P384
	case "ECDSA_SHA512_P521":
		return commonprotocolfern.IkeAuthenticationMethodEcdsaSha512P521
	}
	if alg, err := commonprotocolfern.NewIkeAuthenticationMethodFromString(name); err == nil {
		return alg
	}
	return commonprotocolfern.IkeAuthenticationMethodUnknown
}

func ToFernDHGroup(name string) commonprotocolfern.IkeDhGroup {
	switch name {
	case "MODP-768":
		return commonprotocolfern.IkeDhGroupModp768
	case "MODP-1024":
		return commonprotocolfern.IkeDhGroupModp1024
	case "MODP-1536":
		return commonprotocolfern.IkeDhGroupModp1536
	case "MODP-2048":
		return commonprotocolfern.IkeDhGroupModp2048
	case "MODP-3072":
		return commonprotocolfern.IkeDhGroupModp3072
	case "MODP-4096":
		return commonprotocolfern.IkeDhGroupModp4096
	case "MODP-6144":
		return commonprotocolfern.IkeDhGroupModp6144
	case "MODP-8192":
		return commonprotocolfern.IkeDhGroupModp8192
	case "MODP-1024-160":
		return commonprotocolfern.IkeDhGroupModp1024160
	case "MODP-2048-224":
		return commonprotocolfern.IkeDhGroupModp2048224
	case "MODP-2048-256":
		return commonprotocolfern.IkeDhGroupModp2048256
	case "ECP-192":
		return commonprotocolfern.IkeDhGroupEcp192
	case "ECP-224":
		return commonprotocolfern.IkeDhGroupEcp224
	case "ECP-256":
		return commonprotocolfern.IkeDhGroupEcp256
	case "ECP-384":
		return commonprotocolfern.IkeDhGroupEcp384
	case "ECP-521":
		return commonprotocolfern.IkeDhGroupEcp521
	case "ECP-224-BP":
		return commonprotocolfern.IkeDhGroupEcp224Bp
	case "ECP-256-BP":
		return commonprotocolfern.IkeDhGroupEcp256Bp
	case "ECP-384-BP":
		return commonprotocolfern.IkeDhGroupEcp384Bp
	case "ECP-512-BP":
		return commonprotocolfern.IkeDhGroupEcp512Bp
	case "Curve25519":
		return commonprotocolfern.IkeDhGroupCurve25519
	case "Curve448":
		return commonprotocolfern.IkeDhGroupCurve448
	}
	if group, err := commonprotocolfern.NewIkeDhGroupFromString(name); err == nil {
		return group
	}
	return commonprotocolfern.IkeDhGroupUnknown
}

func MergeFernEncryptionAlgorithms(existing []commonprotocolfern.IkeEncryptionAlgorithm, names []string) []commonprotocolfern.IkeEncryptionAlgorithm {
	for _, name := range names {
		existing = appendUniqueTyped(existing, ToFernEncryptionAlgorithm(name))
	}
	return existing
}

func MergeFernHashAlgorithms(existing []commonprotocolfern.IkeHashAlgorithm, names []string) []commonprotocolfern.IkeHashAlgorithm {
	for _, name := range names {
		existing = appendUniqueTyped(existing, ToFernHashAlgorithm(name))
	}
	return existing
}

func MergeFernAuthenticationMethods(existing []commonprotocolfern.IkeAuthenticationMethod, names []string) []commonprotocolfern.IkeAuthenticationMethod {
	for _, name := range names {
		existing = appendUniqueTyped(existing, ToFernAuthenticationMethod(name))
	}
	return existing
}

func MergeFernDHGroups(existing []commonprotocolfern.IkeDhGroup, names []string) []commonprotocolfern.IkeDhGroup {
	for _, name := range names {
		existing = appendUniqueTyped(existing, ToFernDHGroup(name))
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
