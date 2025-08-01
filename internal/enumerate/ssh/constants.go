package ssh

import (
	commonprotocol "github.com/Method-Security/networkscan/generated/go/common/protocol"
)

var (

	// Key Exchange Algorithms mapped to their enum values
	commonKeyExchangeAlgos = map[string]commonprotocol.KeyExchangeAlgorithm{
		"sntrup761x25519-sha512@openssh.com":   commonprotocol.KeyExchangeAlgorithmSntrup761X25519Sha512Openssh,
		"curve25519-sha256":                    commonprotocol.KeyExchangeAlgorithmCurve25519Sha256,
		"curve25519-sha256@libssh.org":         commonprotocol.KeyExchangeAlgorithmCurve25519Sha256Libssh,
		"ecdh-sha2-nistp256":                   commonprotocol.KeyExchangeAlgorithmEcdhsha2Nistp256,
		"ecdh-sha2-nistp384":                   commonprotocol.KeyExchangeAlgorithmEcdhsha2Nistp384,
		"ecdh-sha2-nistp521":                   commonprotocol.KeyExchangeAlgorithmEcdhsha2Nistp521,
		"ecdh-sha2-nistp224":                   commonprotocol.KeyExchangeAlgorithmEcdhsha2Nistp224,
		"diffie-hellman-group-exchange-sha256": commonprotocol.KeyExchangeAlgorithmDiffiehellmangroupexchangesha256,
		"diffie-hellman-group-exchange-sha512": commonprotocol.KeyExchangeAlgorithmDiffiehellmangroupexchangesha512,
		"diffie-hellman-group16-sha512":        commonprotocol.KeyExchangeAlgorithmDiffiehellmangroup16Sha512,
		"diffie-hellman-group18-sha512":        commonprotocol.KeyExchangeAlgorithmDiffiehellmangroup18Sha512,
		"diffie-hellman-group14-sha256":        commonprotocol.KeyExchangeAlgorithmDiffiehellmangroup14Sha256,
		"diffie-hellman-group14-sha512":        commonprotocol.KeyExchangeAlgorithmDiffiehellmangroup14Sha512,
		"diffie-hellman-group1-sha1":           commonprotocol.KeyExchangeAlgorithmDiffiehellmangroup1Sha1, // Deprecated
		"diffie-hellman-group1-sha256":         commonprotocol.KeyExchangeAlgorithmDiffiehellmangroup1Sha256,
		"kex-strict-s-v00@openssh.com":         commonprotocol.KeyExchangeAlgorithmKexstrictsv00Openssh,
		"x25519-sha256@libssh.org":             commonprotocol.KeyExchangeAlgorithmX25519Sha256Libssh,
		"x448-sha512@openssh.com":              commonprotocol.KeyExchangeAlgorithmX448Sha512Openssh,
		"curve25519-sha512@openssh.com":        commonprotocol.KeyExchangeAlgorithmCurve25519Sha512Openssh,
	}

	// Host Key Algorithms mapped to their enum values
	commonHostKeyAlgos = map[string]commonprotocol.HostKeyAlgorithm{
		"ssh-dss":             commonprotocol.HostKeyAlgorithmSshdss, // Deprecated
		"ssh-rsa":             commonprotocol.HostKeyAlgorithmSshrsa, // Deprecated (SHA-1)
		"rsa-sha2-256":        commonprotocol.HostKeyAlgorithmRsasha2256,
		"rsa-sha2-512":        commonprotocol.HostKeyAlgorithmRsasha2512,
		"ecdsa-sha2-nistp256": commonprotocol.HostKeyAlgorithmEcdsasha2Nistp256,
		"ecdsa-sha2-nistp384": commonprotocol.HostKeyAlgorithmEcdsasha2Nistp384,
		"ecdsa-sha2-nistp521": commonprotocol.HostKeyAlgorithmEcdsasha2Nistp521,
		"ecdsa-sha2-nistp224": commonprotocol.HostKeyAlgorithmEcdsasha2Nistp224,
		"ed25519-sha256":      commonprotocol.HostKeyAlgorithmEd25519Sha256,
	}

	// Cipher Algorithms mapped to their enum values
	commonCiphers = map[string]commonprotocol.CipherAlgorithm{
		"chacha20-poly1305@openssh.com": commonprotocol.CipherAlgorithmChacha20Poly1305Openssh,
		"aes128-ctr":                    commonprotocol.CipherAlgorithmAes128Ctr,
		"aes192-ctr":                    commonprotocol.CipherAlgorithmAes192Ctr,
		"aes256-ctr":                    commonprotocol.CipherAlgorithmAes256Ctr,
		"aes128-gcm@openssh.com":        commonprotocol.CipherAlgorithmAes128Gcmopenssh,
		"aes256-gcm@openssh.com":        commonprotocol.CipherAlgorithmAes256Gcmopenssh,
		"3des-ede3-cbc":                 commonprotocol.CipherAlgorithmThreedescbc,
		"aes128-cbc":                    commonprotocol.CipherAlgorithmAes128Cbc,
		"aes192-cbc":                    commonprotocol.CipherAlgorithmAes192Cbc,
		"aes256-cbc":                    commonprotocol.CipherAlgorithmAes256Cbc,
		"blowfish-cbc":                  commonprotocol.CipherAlgorithmBlowfishcbc,
		"aes128-cbc@openssl.com":        commonprotocol.CipherAlgorithmAes128Cbcopenssl,
	}

	// MAC Algorithms mapped to their enum values
	commonMACs = map[string]commonprotocol.MacAlgorithm{
		"umac-1":                        commonprotocol.MacAlgorithmUmac1,
		"umac-64-etm@openssh.com":       commonprotocol.MacAlgorithmUmac64Etmopenssh,
		"umac-128-etm@openssh.com":      commonprotocol.MacAlgorithmUmac128Etmopenssh,
		"hmac-sha2-256-etm@openssh.com": commonprotocol.MacAlgorithmHmacsha2256Etmopenssh,
		"hmac-sha2-512-etm@openssh.com": commonprotocol.MacAlgorithmHmacsha2512Etmopenssh,
		"hmac-sha1-etm@openssh.com":     commonprotocol.MacAlgorithmHmacsha1Etmopenssh,
		"umac-64@openssh.com":           commonprotocol.MacAlgorithmUmac64Openssh,
		"umac-128@openssh.com":          commonprotocol.MacAlgorithmUmac128Openssh,
		"hmac-sha2-256":                 commonprotocol.MacAlgorithmHmacsha2256,
		"hmac-sha2-512":                 commonprotocol.MacAlgorithmHmacsha2512,
		"hmac-sha1":                     commonprotocol.MacAlgorithmHmacsha1,
		"hmac-md5":                      commonprotocol.MacAlgorithmHmacmd5,
		"hmac-ripemd160":                commonprotocol.MacAlgorithmHmacripemd160,
		"hmac-sha3-256":                 commonprotocol.MacAlgorithmHmacsha3256,
		"hmac-sha3-512":                 commonprotocol.MacAlgorithmHmacsha3512,
	}
)
