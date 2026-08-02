package pkinit

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/jfjallid/gokrb5/v8/iana/patype"
	"github.com/jfjallid/gokrb5/v8/types"
)

// PKINITClient holds the state needed for PKINIT authentication.
type PKINITClient struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	DHKeyPair   *DHKeyPair
	DHNonce     []byte // Client DH nonce for key derivation
}

// NewPKINITClient creates a PKINIT client from PFX file bytes and password.
func NewPKINITClient(pfxData []byte, password string) (*PKINITClient, error) {
	privateKey, cert, err := ParsePFX(pfxData, password)
	if err != nil {
		return nil, err
	}

	return &PKINITClient{
		Certificate: cert,
		PrivateKey:  privateKey,
	}, nil
}

// BuildPAPKASReq constructs the PA-PK-AS-REQ PAData for the AS-REQ.
//
// Parameters:
//   - reqBodyBytes: DER-encoded KDC-REQ-BODY (for paChecksum)
//   - nonce: the nonce from the AS-REQ
//   - cusec: microseconds component of the timestamp
//   - ctime: the timestamp
func (p *PKINITClient) BuildPAPKASReq(reqBodyBytes []byte, nonce int, cusec int, ctime time.Time) (types.PAData, error) {
	// 1. Generate DH key pair
	dhKeyPair, err := GenerateDHKeyPair()
	if err != nil {
		return types.PAData{}, fmt.Errorf("failed to generate DH key pair: %w", err)
	}
	p.DHKeyPair = dhKeyPair

	// 2. Generate client DH nonce
	dhNonce, err := GenerateDHNonce()
	if err != nil {
		return types.PAData{}, fmt.Errorf("failed to generate DH nonce: %w", err)
	}
	p.DHNonce = dhNonce

	// 3. Compute paChecksum = SHA1(KDC-REQ-BODY)
	checksum := sha1.Sum(reqBodyBytes)

	// 4. Build PKAuthenticator
	pkAuth := PKAuthenticator{
		CUSec:      cusec,
		CTime:      ctime,
		Nonce:      nonce,
		PAChecksum: checksum[:],
	}

	// 6. Build SubjectPublicKeyInfo for DH
	dhParams, err := EncodeDHParameters(dhKeyPair.P, dhKeyPair.G, dhKeyPair.Q)
	if err != nil {
		return types.PAData{}, fmt.Errorf("failed to encode DH parameters: %w", err)
	}

	clientPubKey := SubjectPublicKeyInfo{
		Algorithm: AlgorithmIdentifier{
			Algorithm:  OIDDiffieHellman,
			Parameters: dhParams,
		},
		PublicKey: EncodeDHPublicKey(dhKeyPair.Public),
	}

	// 7. Build AuthPack
	authPack := AuthPack{
		PKAuthenticator:   pkAuth,
		ClientPublicValue: clientPubKey,
		ClientDHNonce:     dhNonce,
	}

	// 8. Marshal AuthPack
	authPackBytes, err := asn1.Marshal(authPack)
	if err != nil {
		return types.PAData{}, fmt.Errorf("failed to marshal AuthPack: %w", err)
	}

	// 9. Build CMS SignedData over AuthPack
	signedAuthPack, err := BuildSignedAuthPack(authPackBytes, p.Certificate, p.PrivateKey)
	if err != nil {
		return types.PAData{}, fmt.Errorf("failed to build signed AuthPack: %w", err)
	}

	// 10. Build PA-PK-AS-REQ
	paPkAsReq := PAPKASReq{
		SignedAuthPack: signedAuthPack,
	}

	paPkAsReqBytes, err := asn1.Marshal(paPkAsReq)
	if err != nil {
		return types.PAData{}, fmt.Errorf("failed to marshal PA-PK-AS-REQ: %w", err)
	}

	return types.PAData{
		PADataType:  patype.PA_PK_AS_REQ,
		PADataValue: paPkAsReqBytes,
	}, nil
}

// ProcessPAPKASRep processes the KDC's PA-PK-AS-REP response and derives the session key.
//
// Parameters:
//   - padata: the PA-PK-AS-REP PAData from the AS-REP
//   - etypeID: the encryption type of the AS-REP's EncPart
//
// Returns the derived encryption key used to decrypt the AS-REP EncPart.
func (p *PKINITClient) ProcessPAPKASRep(padata types.PAData, etypeID int32) (types.EncryptionKey, error) {
	// 1. PA-PK-AS-REP is a CHOICE, not a SEQUENCE. Parse the outer tag to determine mode.
	var raw asn1.RawValue
	_, err := asn1.Unmarshal(padata.PADataValue, &raw)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("failed to unmarshal PA-PK-AS-REP: %w", err)
	}

	// 2. Check which CHOICE variant: [0] = DHInfo, [1] = EncKeyPack
	if raw.Class != asn1.ClassContextSpecific || raw.Tag != 0 {
		return types.EncryptionKey{}, fmt.Errorf("PA-PK-AS-REP is not DH mode (tag: class=%d tag=%d), RSA mode not supported", raw.Class, raw.Tag)
	}

	// 3. Unmarshal the inner content as DHRepInfo SEQUENCE
	var dhInfo DHRepInfo
	_, err = asn1.Unmarshal(raw.Bytes, &dhInfo)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("failed to unmarshal DHRepInfo: %w", err)
	}

	if len(dhInfo.DHSignedData) == 0 {
		return types.EncryptionKey{}, fmt.Errorf("DHRepInfo has empty DHSignedData")
	}

	// 4. Extract KDCDHKeyInfo from the signed data
	kdcKeyInfo, err := ExtractKDCDHKeyInfo(dhInfo.DHSignedData)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("failed to extract KDC DH key info: %w", err)
	}

	// 5. Decode the KDC's DH public key
	kdcPub, err := DecodeDHPublicKey(kdcKeyInfo.SubjectPublicKey)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("failed to decode KDC DH public key: %w", err)
	}

	// 6. Compute DH shared secret
	sharedSecret := ComputeDHSharedSecret(p.DHKeyPair.Private, kdcPub, p.DHKeyPair.P)

	// 7. Derive session key using OctetString2Key
	// Prime size in bytes for DH shared secret padding
	primeSize := len(p.DHKeyPair.P.Bytes())
	key, err := OctetString2Key(sharedSecret, etypeID, p.DHNonce, dhInfo.ServerDHNonce, primeSize)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("failed to derive session key: %w", err)
	}

	return key, nil
}
