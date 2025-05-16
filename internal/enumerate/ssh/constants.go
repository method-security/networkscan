package ssh

import (
	ssh "github.com/Method-Security/networkscan/generated/go/enumerate/ssh"
)

var (

	// Key Exchange Algorithms mapped to their enum values
	commonKeyExchangeAlgos = map[string]ssh.KeyExchangeAlgorithm{
		"sntrup761x25519-sha512@openssh.com":   ssh.KeyExchangeAlgorithmSntrup761X25519Sha512Openssh,
		"curve25519-sha256":                    ssh.KeyExchangeAlgorithmCurve25519Sha256,
		"curve25519-sha256@libssh.org":         ssh.KeyExchangeAlgorithmCurve25519Sha256Libssh,
		"ecdh-sha2-nistp256":                   ssh.KeyExchangeAlgorithmEcdhsha2Nistp256,
		"ecdh-sha2-nistp384":                   ssh.KeyExchangeAlgorithmEcdhsha2Nistp384,
		"ecdh-sha2-nistp521":                   ssh.KeyExchangeAlgorithmEcdhsha2Nistp521,
		"ecdh-sha2-nistp224":                   ssh.KeyExchangeAlgorithmEcdhsha2Nistp224,
		"diffie-hellman-group-exchange-sha256": ssh.KeyExchangeAlgorithmDiffiehellmangroupexchangesha256,
		"diffie-hellman-group-exchange-sha512": ssh.KeyExchangeAlgorithmDiffiehellmangroupexchangesha512,
		"diffie-hellman-group16-sha512":        ssh.KeyExchangeAlgorithmDiffiehellmangroup16Sha512,
		"diffie-hellman-group18-sha512":        ssh.KeyExchangeAlgorithmDiffiehellmangroup18Sha512,
		"diffie-hellman-group14-sha256":        ssh.KeyExchangeAlgorithmDiffiehellmangroup14Sha256,
		"diffie-hellman-group14-sha512":        ssh.KeyExchangeAlgorithmDiffiehellmangroup14Sha512,
		"diffie-hellman-group1-sha1":           ssh.KeyExchangeAlgorithmDiffiehellmangroup1Sha1, // Deprecated
		"diffie-hellman-group1-sha256":         ssh.KeyExchangeAlgorithmDiffiehellmangroup1Sha256,
		"kex-strict-s-v00@openssh.com":         ssh.KeyExchangeAlgorithmKexstrictsv00Openssh,
		"x25519-sha256@libssh.org":             ssh.KeyExchangeAlgorithmX25519Sha256Libssh,
		"x448-sha512@openssh.com":              ssh.KeyExchangeAlgorithmX448Sha512Openssh,
		"curve25519-sha512@openssh.com":        ssh.KeyExchangeAlgorithmCurve25519Sha512Openssh,
	}

	// Host Key Algorithms mapped to their enum values
	commonHostKeyAlgos = map[string]ssh.HostKeyAlgorithm{
		"ssh-dss":             ssh.HostKeyAlgorithmSshdss, // Deprecated
		"ssh-rsa":             ssh.HostKeyAlgorithmSshrsa, // Deprecated (SHA-1)
		"rsa-sha2-256":        ssh.HostKeyAlgorithmRsasha2256,
		"rsa-sha2-512":        ssh.HostKeyAlgorithmRsasha2512,
		"ecdsa-sha2-nistp256": ssh.HostKeyAlgorithmEcdsasha2Nistp256,
		"ecdsa-sha2-nistp384": ssh.HostKeyAlgorithmEcdsasha2Nistp384,
		"ecdsa-sha2-nistp521": ssh.HostKeyAlgorithmEcdsasha2Nistp521,
		"ecdsa-sha2-nistp224": ssh.HostKeyAlgorithmEcdsasha2Nistp224,
		"ed25519-sha256":      ssh.HostKeyAlgorithmEd25519Sha256,
	}

	// Cipher Algorithms mapped to their enum values
	commonCiphers = map[string]ssh.CipherAlgorithm{
		"chacha20-poly1305@openssh.com": ssh.CipherAlgorithmChacha20Poly1305Openssh,
		"aes128-ctr":                    ssh.CipherAlgorithmAes128Ctr,
		"aes192-ctr":                    ssh.CipherAlgorithmAes192Ctr,
		"aes256-ctr":                    ssh.CipherAlgorithmAes256Ctr,
		"aes128-gcm@openssh.com":        ssh.CipherAlgorithmAes128Gcmopenssh,
		"aes256-gcm@openssh.com":        ssh.CipherAlgorithmAes256Gcmopenssh,
		"3des-ede3-cbc":                 ssh.CipherAlgorithmThreedescbc,
		"aes128-cbc":                    ssh.CipherAlgorithmAes128Cbc,
		"aes192-cbc":                    ssh.CipherAlgorithmAes192Cbc,
		"aes256-cbc":                    ssh.CipherAlgorithmAes256Cbc,
		"blowfish-cbc":                  ssh.CipherAlgorithmBlowfishcbc,
		"aes128-cbc@openssl.com":        ssh.CipherAlgorithmAes128Cbcopenssl,
	}

	// MAC Algorithms mapped to their enum values
	commonMACs = map[string]ssh.MacAlgorithm{
		"umac-1":                        ssh.MacAlgorithmUmac1,
		"umac-64-etm@openssh.com":       ssh.MacAlgorithmUmac64Etmopenssh,
		"umac-128-etm@openssh.com":      ssh.MacAlgorithmUmac128Etmopenssh,
		"hmac-sha2-256-etm@openssh.com": ssh.MacAlgorithmHmacsha2256Etmopenssh,
		"hmac-sha2-512-etm@openssh.com": ssh.MacAlgorithmHmacsha2512Etmopenssh,
		"hmac-sha1-etm@openssh.com":     ssh.MacAlgorithmHmacsha1Etmopenssh,
		"umac-64@openssh.com":           ssh.MacAlgorithmUmac64Openssh,
		"umac-128@openssh.com":          ssh.MacAlgorithmUmac128Openssh,
		"hmac-sha2-256":                 ssh.MacAlgorithmHmacsha2256,
		"hmac-sha2-512":                 ssh.MacAlgorithmHmacsha2512,
		"hmac-sha1":                     ssh.MacAlgorithmHmacsha1,
		"hmac-md5":                      ssh.MacAlgorithmHmacmd5,
		"hmac-ripemd160":                ssh.MacAlgorithmHmacripemd160,
		"hmac-sha3-256":                 ssh.MacAlgorithmHmacsha3256,
		"hmac-sha3-512":                 ssh.MacAlgorithmHmacsha3512,
	}
)
