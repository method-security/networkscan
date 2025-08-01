package ssh

import (
	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
)

var (

	// Key Exchange Algorithms mapped to their enum values
	commonKeyExchangeAlgos = map[string]commonprotocolfern.KeyExchangeAlgorithm{
		"sntrup761x25519-sha512@openssh.com":   commonprotocolfern.KeyExchangeAlgorithmSntrup761X25519Sha512Openssh,
		"curve25519-sha256":                    commonprotocolfern.KeyExchangeAlgorithmCurve25519Sha256,
		"curve25519-sha256@libssh.org":         commonprotocolfern.KeyExchangeAlgorithmCurve25519Sha256Libssh,
		"ecdh-sha2-nistp256":                   commonprotocolfern.KeyExchangeAlgorithmEcdhsha2Nistp256,
		"ecdh-sha2-nistp384":                   commonprotocolfern.KeyExchangeAlgorithmEcdhsha2Nistp384,
		"ecdh-sha2-nistp521":                   commonprotocolfern.KeyExchangeAlgorithmEcdhsha2Nistp521,
		"ecdh-sha2-nistp224":                   commonprotocolfern.KeyExchangeAlgorithmEcdhsha2Nistp224,
		"diffie-hellman-group-exchange-sha256": commonprotocolfern.KeyExchangeAlgorithmDiffiehellmangroupexchangesha256,
		"diffie-hellman-group-exchange-sha512": commonprotocolfern.KeyExchangeAlgorithmDiffiehellmangroupexchangesha512,
		"diffie-hellman-group16-sha512":        commonprotocolfern.KeyExchangeAlgorithmDiffiehellmangroup16Sha512,
		"diffie-hellman-group18-sha512":        commonprotocolfern.KeyExchangeAlgorithmDiffiehellmangroup18Sha512,
		"diffie-hellman-group14-sha256":        commonprotocolfern.KeyExchangeAlgorithmDiffiehellmangroup14Sha256,
		"diffie-hellman-group14-sha512":        commonprotocolfern.KeyExchangeAlgorithmDiffiehellmangroup14Sha512,
		"diffie-hellman-group1-sha1":           commonprotocolfern.KeyExchangeAlgorithmDiffiehellmangroup1Sha1, // Deprecated
		"diffie-hellman-group1-sha256":         commonprotocolfern.KeyExchangeAlgorithmDiffiehellmangroup1Sha256,
		"kex-strict-s-v00@openssh.com":         commonprotocolfern.KeyExchangeAlgorithmKexstrictsv00Openssh,
		"x25519-sha256@libssh.org":             commonprotocolfern.KeyExchangeAlgorithmX25519Sha256Libssh,
		"x448-sha512@openssh.com":              commonprotocolfern.KeyExchangeAlgorithmX448Sha512Openssh,
		"curve25519-sha512@openssh.com":        commonprotocolfern.KeyExchangeAlgorithmCurve25519Sha512Openssh,
	}

	// Host Key Algorithms mapped to their enum values
	commonHostKeyAlgos = map[string]commonprotocolfern.HostKeyAlgorithm{
		"ssh-dss":             commonprotocolfern.HostKeyAlgorithmSshdss, // Deprecated
		"ssh-rsa":             commonprotocolfern.HostKeyAlgorithmSshrsa, // Deprecated (SHA-1)
		"rsa-sha2-256":        commonprotocolfern.HostKeyAlgorithmRsasha2256,
		"rsa-sha2-512":        commonprotocolfern.HostKeyAlgorithmRsasha2512,
		"ecdsa-sha2-nistp256": commonprotocolfern.HostKeyAlgorithmEcdsasha2Nistp256,
		"ecdsa-sha2-nistp384": commonprotocolfern.HostKeyAlgorithmEcdsasha2Nistp384,
		"ecdsa-sha2-nistp521": commonprotocolfern.HostKeyAlgorithmEcdsasha2Nistp521,
		"ecdsa-sha2-nistp224": commonprotocolfern.HostKeyAlgorithmEcdsasha2Nistp224,
		"ed25519-sha256":      commonprotocolfern.HostKeyAlgorithmEd25519Sha256,
	}

	// Cipher Algorithms mapped to their enum values
	commonCiphers = map[string]commonprotocolfern.CipherAlgorithm{
		"chacha20-poly1305@openssh.com": commonprotocolfern.CipherAlgorithmChacha20Poly1305Openssh,
		"aes128-ctr":                    commonprotocolfern.CipherAlgorithmAes128Ctr,
		"aes192-ctr":                    commonprotocolfern.CipherAlgorithmAes192Ctr,
		"aes256-ctr":                    commonprotocolfern.CipherAlgorithmAes256Ctr,
		"aes128-gcm@openssh.com":        commonprotocolfern.CipherAlgorithmAes128Gcmopenssh,
		"aes256-gcm@openssh.com":        commonprotocolfern.CipherAlgorithmAes256Gcmopenssh,
		"3des-ede3-cbc":                 commonprotocolfern.CipherAlgorithmThreedescbc,
		"aes128-cbc":                    commonprotocolfern.CipherAlgorithmAes128Cbc,
		"aes192-cbc":                    commonprotocolfern.CipherAlgorithmAes192Cbc,
		"aes256-cbc":                    commonprotocolfern.CipherAlgorithmAes256Cbc,
		"blowfish-cbc":                  commonprotocolfern.CipherAlgorithmBlowfishcbc,
		"aes128-cbc@openssl.com":        commonprotocolfern.CipherAlgorithmAes128Cbcopenssl,
	}

	// MAC Algorithms mapped to their enum values
	commonMACs = map[string]commonprotocolfern.MacAlgorithm{
		"umac-1":                        commonprotocolfern.MacAlgorithmUmac1,
		"umac-64-etm@openssh.com":       commonprotocolfern.MacAlgorithmUmac64Etmopenssh,
		"umac-128-etm@openssh.com":      commonprotocolfern.MacAlgorithmUmac128Etmopenssh,
		"hmac-sha2-256-etm@openssh.com": commonprotocolfern.MacAlgorithmHmacsha2256Etmopenssh,
		"hmac-sha2-512-etm@openssh.com": commonprotocolfern.MacAlgorithmHmacsha2512Etmopenssh,
		"hmac-sha1-etm@openssh.com":     commonprotocolfern.MacAlgorithmHmacsha1Etmopenssh,
		"umac-64@openssh.com":           commonprotocolfern.MacAlgorithmUmac64Openssh,
		"umac-128@openssh.com":          commonprotocolfern.MacAlgorithmUmac128Openssh,
		"hmac-sha2-256":                 commonprotocolfern.MacAlgorithmHmacsha2256,
		"hmac-sha2-512":                 commonprotocolfern.MacAlgorithmHmacsha2512,
		"hmac-sha1":                     commonprotocolfern.MacAlgorithmHmacsha1,
		"hmac-md5":                      commonprotocolfern.MacAlgorithmHmacmd5,
		"hmac-ripemd160":                commonprotocolfern.MacAlgorithmHmacripemd160,
		"hmac-sha3-256":                 commonprotocolfern.MacAlgorithmHmacsha3256,
		"hmac-sha3-512":                 commonprotocolfern.MacAlgorithmHmacsha3512,
	}
)
