package pkinit

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/jfjallid/gokrb5/v8/crypto"
	"github.com/jfjallid/gokrb5/v8/types"
)

// Oakley Group 2 (RFC 2409) - 1024-bit MODP group, default for AD PKINIT
var oakleyGroup2P *big.Int
var oakleyGroup2G *big.Int
var oakleyGroup2Q *big.Int

// Oakley Group 14 (RFC 3526) - 2048-bit MODP group
var oakleyGroup14P *big.Int
var oakleyGroup14G *big.Int
var oakleyGroup14Q *big.Int

func init() {
	oakleyGroup2P, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
			"FFFFFFFFFFFFFFFF", 16)
	oakleyGroup2G = big.NewInt(2)
	// Q = (P-1)/2
	oakleyGroup2Q = new(big.Int).Rsh(oakleyGroup2P, 1)

	oakleyGroup14P, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	oakleyGroup14G = big.NewInt(2)
	oakleyGroup14Q = new(big.Int).Rsh(oakleyGroup14P, 1)
}

// DHKeyPair holds DH private/public key pair and parameters.
type DHKeyPair struct {
	Private *big.Int
	Public  *big.Int
	P       *big.Int
	G       *big.Int
	Q       *big.Int
}

// GenerateDHKeyPair generates a DH key pair using Oakley Group 2 parameters.
func GenerateDHKeyPair() (*DHKeyPair, error) {
	return generateDHKeyPairWithParams(oakleyGroup2P, oakleyGroup2G, oakleyGroup2Q)
}

func generateDHKeyPairWithParams(p, g, q *big.Int) (*DHKeyPair, error) {
	// Generate random private key x in [2, q-1]
	// For Oakley groups, q = (p-1)/2, so x should be in [2, q-1]
	qMinus2 := new(big.Int).Sub(q, big.NewInt(2))
	x, err := rand.Int(rand.Reader, qMinus2)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DH private key: %w", err)
	}
	x.Add(x, big.NewInt(2)) // Shift range from [0, q-3] to [2, q-1]

	// Compute public key: g^x mod p
	y := new(big.Int).Exp(g, x, p)

	return &DHKeyPair{
		Private: x,
		Public:  y,
		P:       p,
		G:       g,
		Q:       q,
	}, nil
}

// ComputeDHSharedSecret computes the DH shared secret: theirPublic^myPrivate mod p
func ComputeDHSharedSecret(myPrivate, theirPublic, p *big.Int) *big.Int {
	return new(big.Int).Exp(theirPublic, myPrivate, p)
}

// EncodeDHPublicKey encodes a DH public key as an ASN.1 INTEGER wrapped in a BIT STRING.
func EncodeDHPublicKey(pub *big.Int) asn1.BitString {
	// The public key is encoded as a DER INTEGER inside a BIT STRING
	pubBytes, _ := asn1.Marshal(pub)
	return asn1.BitString{
		Bytes:     pubBytes,
		BitLength: len(pubBytes) * 8,
	}
}

// DecodeDHPublicKey decodes a DH public key from a BIT STRING containing an ASN.1 INTEGER.
func DecodeDHPublicKey(bs asn1.BitString) (*big.Int, error) {
	var pub *big.Int
	_, err := asn1.Unmarshal(bs.Bytes, &pub)
	if err != nil {
		return nil, fmt.Errorf("failed to decode DH public key: %w", err)
	}
	return pub, nil
}

// EncodeDHParameters DER-encodes the DH domain parameters for SubjectPublicKeyInfo.Algorithm.Parameters.
func EncodeDHParameters(p, g, q *big.Int) (asn1.RawValue, error) {
	params := DomainParameters{
		P: p,
		G: g,
		Q: q,
	}
	b, err := asn1.Marshal(params)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("failed to marshal DH parameters: %w", err)
	}
	return asn1.RawValue{FullBytes: b}, nil
}

// OctetString2Key derives a Kerberos session key from DH shared secret per RFC 4556 Section 3.2.3.1.
//
// The key derivation:
//  1. x = DHSharedSecret padded with leading zeros to the size of prime p
//  2. If serverDHNonce present: x = x || clientDHNonce || serverDHNonce
//  3. Generate key material using SHA-1 PRF: SHA1(counter || x) for counter = 0, 1, 2, ...
//  4. K-truncate to etype key byte size
//  5. Pass through etype.RandomToKey()
func OctetString2Key(sharedSecret *big.Int, etypeID int32, clientDHNonce, serverDHNonce []byte, primeSize int) (types.EncryptionKey, error) {
	et, err := crypto.GetEtype(etypeID)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("failed to get etype %d: %w", etypeID, err)
	}

	// Get the shared secret bytes (big-endian), padded with leading zeros to the size of prime p
	// RFC 4556 Section 3.2.3.1: "DHSharedSecret is first padded with leading zeros such that
	// the size of DHSharedSecret in octets is the same as that of the DH modulus p"
	secretBytes := sharedSecret.Bytes()
	if len(secretBytes) < primeSize {
		padded := make([]byte, primeSize)
		copy(padded[primeSize-len(secretBytes):], secretBytes)
		secretBytes = padded
	}

	// Build x: only concatenate nonces when serverDHNonce is present
	// RFC 4556: if both nonce values differ, x = DHSharedSecret || clientDHNonce || serverDHNonce
	x := make([]byte, len(secretBytes))
	copy(x, secretBytes)
	if len(serverDHNonce) > 0 && len(clientDHNonce) > 0 {
		x = append(x, clientDHNonce...)
		x = append(x, serverDHNonce...)
	}

	keySize := et.GetKeyByteSize()

	// Generate sufficient key material using SHA-1 PRF+
	// PRF+(x) = SHA1(0x00 || x) || SHA1(0x01 || x) || SHA1(0x02 || x) || ...
	var keyMaterial []byte
	for counter := byte(0); len(keyMaterial) < keySize; counter++ {
		h := sha1.New()
		h.Write([]byte{counter})
		h.Write(x)
		keyMaterial = append(keyMaterial, h.Sum(nil)...)
	}

	// K-truncate: take first keySize bytes
	truncated := keyMaterial[:keySize]

	// random-to-key
	key := et.RandomToKey(truncated)

	return types.EncryptionKey{
		KeyType:  etypeID,
		KeyValue: key,
	}, nil
}

// GenerateDHNonce generates a random DH nonce (used for key derivation).
// AD typically uses a 32-byte nonce.
func GenerateDHNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DH nonce: %w", err)
	}
	return nonce, nil
}
