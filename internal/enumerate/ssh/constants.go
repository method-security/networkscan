package ssh

import (
	sshFern "github.com/Method-Security/networkscan/generated/go/enumerate/ssh"
)

var (

	// Key Exchange Algorithms mapped to their enum values
	commonKeyExchangeAlgos = map[string]sshFern.KeyExchangeAlgorithm{
		"sntrup761x25519-sha512@openssh.com":   sshFern.KeyExchangeAlgorithmSntrup761X25519Sha512Openssh,
		"curve25519-sha256":                    sshFern.KeyExchangeAlgorithmCurve25519Sha256,
		"curve25519-sha256@libssh.org":         sshFern.KeyExchangeAlgorithmCurve25519Sha256Libssh,
		"ecdh-sha2-nistp256":                   sshFern.KeyExchangeAlgorithmEcdhsha2Nistp256,
		"ecdh-sha2-nistp384":                   sshFern.KeyExchangeAlgorithmEcdhsha2Nistp384,
		"ecdh-sha2-nistp521":                   sshFern.KeyExchangeAlgorithmEcdhsha2Nistp521,
		"ecdh-sha2-nistp224":                   sshFern.KeyExchangeAlgorithmEcdhsha2Nistp224,
		"diffie-hellman-group-exchange-sha256": sshFern.KeyExchangeAlgorithmDiffiehellmangroupexchangesha256,
		"diffie-hellman-group-exchange-sha512": sshFern.KeyExchangeAlgorithmDiffiehellmangroupexchangesha512,
		"diffie-hellman-group16-sha512":        sshFern.KeyExchangeAlgorithmDiffiehellmangroup16Sha512,
		"diffie-hellman-group18-sha512":        sshFern.KeyExchangeAlgorithmDiffiehellmangroup18Sha512,
		"diffie-hellman-group14-sha256":        sshFern.KeyExchangeAlgorithmDiffiehellmangroup14Sha256,
		"diffie-hellman-group14-sha512":        sshFern.KeyExchangeAlgorithmDiffiehellmangroup14Sha512,
		"diffie-hellman-group1-sha1":           sshFern.KeyExchangeAlgorithmDiffiehellmangroup1Sha1, // Deprecated
		"diffie-hellman-group1-sha256":         sshFern.KeyExchangeAlgorithmDiffiehellmangroup1Sha256,
		"kex-strict-s-v00@openssh.com":         sshFern.KeyExchangeAlgorithmKexstrictsv00Openssh,
		"x25519-sha256@libssh.org":             sshFern.KeyExchangeAlgorithmX25519Sha256Libssh,
		"x448-sha512@openssh.com":              sshFern.KeyExchangeAlgorithmX448Sha512Openssh,
		"curve25519-sha512@openssh.com":        sshFern.KeyExchangeAlgorithmCurve25519Sha512Openssh,
	}

	// Host Key Algorithms mapped to their enum values
	commonHostKeyAlgos = map[string]sshFern.HostKeyAlgorithm{
		"ssh-dss":             sshFern.HostKeyAlgorithmSshdss, // Deprecated
		"ssh-rsa":             sshFern.HostKeyAlgorithmSshrsa, // Deprecated (SHA-1)
		"rsa-sha2-256":        sshFern.HostKeyAlgorithmRsasha2256,
		"rsa-sha2-512":        sshFern.HostKeyAlgorithmRsasha2512,
		"ecdsa-sha2-nistp256": sshFern.HostKeyAlgorithmEcdsasha2Nistp256,
		"ecdsa-sha2-nistp384": sshFern.HostKeyAlgorithmEcdsasha2Nistp384,
		"ecdsa-sha2-nistp521": sshFern.HostKeyAlgorithmEcdsasha2Nistp521,
		"ecdsa-sha2-nistp224": sshFern.HostKeyAlgorithmEcdsasha2Nistp224,
		"ed25519-sha256":      sshFern.HostKeyAlgorithmEd25519Sha256,
	}

	// Cipher Algorithms mapped to their enum values
	commonCiphers = map[string]sshFern.CipherAlgorithm{
		"chacha20-poly1305@openssh.com": sshFern.CipherAlgorithmChacha20Poly1305Openssh,
		"aes128-ctr":                    sshFern.CipherAlgorithmAes128Ctr,
		"aes192-ctr":                    sshFern.CipherAlgorithmAes192Ctr,
		"aes256-ctr":                    sshFern.CipherAlgorithmAes256Ctr,
		"aes128-gcm@openssh.com":        sshFern.CipherAlgorithmAes128Gcmopenssh,
		"aes256-gcm@openssh.com":        sshFern.CipherAlgorithmAes256Gcmopenssh,
		"3des-ede3-cbc":                 sshFern.CipherAlgorithmThreedescbc,
		"aes128-cbc":                    sshFern.CipherAlgorithmAes128Cbc,
		"aes192-cbc":                    sshFern.CipherAlgorithmAes192Cbc,
		"aes256-cbc":                    sshFern.CipherAlgorithmAes256Cbc,
		"blowfish-cbc":                  sshFern.CipherAlgorithmBlowfishcbc,
		"aes128-cbc@openssl.com":        sshFern.CipherAlgorithmAes128Cbcopenssl,
	}

	// MAC Algorithms mapped to their enum values
	commonMACs = map[string]sshFern.MacAlgorithm{
		"umac-1":                        sshFern.MacAlgorithmUmac1,
		"umac-64-etm@openssh.com":       sshFern.MacAlgorithmUmac64Etmopenssh,
		"umac-128-etm@openssh.com":      sshFern.MacAlgorithmUmac128Etmopenssh,
		"hmac-sha2-256-etm@openssh.com": sshFern.MacAlgorithmHmacsha2256Etmopenssh,
		"hmac-sha2-512-etm@openssh.com": sshFern.MacAlgorithmHmacsha2512Etmopenssh,
		"hmac-sha1-etm@openssh.com":     sshFern.MacAlgorithmHmacsha1Etmopenssh,
		"umac-64@openssh.com":           sshFern.MacAlgorithmUmac64Openssh,
		"umac-128@openssh.com":          sshFern.MacAlgorithmUmac128Openssh,
		"hmac-sha2-256":                 sshFern.MacAlgorithmHmacsha2256,
		"hmac-sha2-512":                 sshFern.MacAlgorithmHmacsha2512,
		"hmac-sha1":                     sshFern.MacAlgorithmHmacsha1,
		"hmac-md5":                      sshFern.MacAlgorithmHmacmd5,
		"hmac-ripemd160":                sshFern.MacAlgorithmHmacripemd160,
		"hmac-sha3-256":                 sshFern.MacAlgorithmHmacsha3256,
		"hmac-sha3-512":                 sshFern.MacAlgorithmHmacsha3512,
	}
)
