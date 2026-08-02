// Package crypto implements cryptographic functions for Kerberos 5 implementation.
package crypto

import (
	"encoding/hex"
	"fmt"

	"github.com/jfjallid/gokrb5/v9/crypto/etype"
	"github.com/jfjallid/gokrb5/v9/iana/chksumtype"
	"github.com/jfjallid/gokrb5/v9/iana/etypeID"
	"github.com/jfjallid/gokrb5/v9/iana/patype"
	"github.com/jfjallid/gokrb5/v9/types"
)

// GetEtype returns an instances of the required etype struct for the etype ID.
func GetEtype(id int32) (etype.EType, error) {
	switch id {
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		var et Aes128CtsHmacSha96
		return et, nil
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		var et Aes256CtsHmacSha96
		return et, nil
	case etypeID.AES128_CTS_HMAC_SHA256_128:
		var et Aes128CtsHmacSha256128
		return et, nil
	case etypeID.AES256_CTS_HMAC_SHA384_192:
		var et Aes256CtsHmacSha384192
		return et, nil
	case etypeID.RC4_HMAC:
		var et RC4HMAC
		return et, nil
	default:
		return nil, fmt.Errorf("unknown or unsupported EType: %d", id)
	}
}

// GetChksumEtype returns an instances of the required etype struct for the checksum ID.
func GetChksumEtype(id int32) (etype.EType, error) {
	switch id {
	case chksumtype.HMAC_SHA1_96_AES128:
		var et Aes128CtsHmacSha96
		return et, nil
	case chksumtype.HMAC_SHA1_96_AES256:
		var et Aes256CtsHmacSha96
		return et, nil
	case chksumtype.HMAC_SHA256_128_AES128:
		var et Aes128CtsHmacSha256128
		return et, nil
	case chksumtype.HMAC_SHA384_192_AES256:
		var et Aes256CtsHmacSha384192
		return et, nil
	case chksumtype.KERB_CHECKSUM_HMAC_MD5:
		var et RC4HMAC
		return et, nil
	//case chksumtype.KERB_CHECKSUM_HMAC_MD5_UNSIGNED:
	//	var et RC4HMAC
	//	return et, nil
	default:
		return nil, fmt.Errorf("unknown or unsupported checksum type: %d", id)
	}
}

// GetKeyFromPassword generates an encryption key from the principal's password.
func GetKeyFromPassword(passwd string, cname types.PrincipalName, realm string, etID int32, pas types.PADataSequence) (types.EncryptionKey, etype.EType, error) {
	var key types.EncryptionKey
	et, err := GetEtype(etID)
	if err != nil {
		return key, et, fmt.Errorf("error getting encryption type: %v", err)
	}
	sk2p := et.GetDefaultStringToKeyParams()
	var salt string
	var paID int32
	for _, pa := range pas {
		switch pa.PADataType {
		case patype.PA_PW_SALT:
			if paID > pa.PADataType {
				continue
			}
			salt = string(pa.PADataValue)
			paID = pa.PADataType
		case patype.PA_ETYPE_INFO:
			if paID > pa.PADataType {
				continue
			}
			var eti types.ETypeInfo
			err := eti.Unmarshal(pa.PADataValue)
			if err != nil {
				return key, et, fmt.Errorf("error unmashaling PA Data to PA-ETYPE-INFO2: %v", err)
			}
			// PA data can originate from an unauthenticated KRBError; an empty but
			// well-formed ETYPE-INFO SEQUENCE must not panic on eti[0].
			if len(eti) == 0 {
				continue
			}
			if etID != eti[0].EType {
				et, err = GetEtype(eti[0].EType)
				if err != nil {
					return key, et, fmt.Errorf("error getting encryption type: %v", err)
				}
			}
			salt = string(eti[0].Salt)
			paID = pa.PADataType
		case patype.PA_ETYPE_INFO2:
			if paID > pa.PADataType {
				continue
			}
			var et2 types.ETypeInfo2
			err := et2.Unmarshal(pa.PADataValue)
			if err != nil {
				return key, et, fmt.Errorf("error unmashalling PA Data to PA-ETYPE-INFO2: %v", err)
			}
			if len(et2) == 0 {
				continue
			}
			if etID != et2[0].EType {
				et, err = GetEtype(et2[0].EType)
				if err != nil {
					return key, et, fmt.Errorf("error getting encryption type: %v", err)
				}
			}
			if len(et2[0].S2KParams) == 4 {
				sk2p = hex.EncodeToString(et2[0].S2KParams)
			}
			salt = et2[0].Salt
			paID = pa.PADataType
		}
	}
	if salt == "" {
		salt = cname.GetSalt(realm)
	}
	k, err := et.StringToKey(passwd, salt, sk2p)
	if err != nil {
		return key, et, fmt.Errorf("error deriving key from string: %+v", err)
	}
	key = types.EncryptionKey{
		KeyType:  etID,
		KeyValue: k,
	}
	return key, et, nil
}

// GetKeyFromHash builds an encryption key directly from a pre-computed key value
// (an NT hash for RC4-HMAC, or a raw AES key) for enctype etID.
//
// Unlike GetKeyFromPassword, no string-to-key derivation is performed: the hash
// IS the key, so the cname, realm and pas parameters are NOT used. They are
// retained only to mirror GetKeyFromPassword's signature so the two are
// interchangeable at call sites; pass zero values if you have none.
func GetKeyFromHash(hash []byte, _ types.PrincipalName, _ string, etID int32, _ types.PADataSequence) (types.EncryptionKey, etype.EType, error) {
	var key types.EncryptionKey
	et, err := GetEtype(etID)
	if err != nil {
		return key, et, fmt.Errorf("error getting encryption type: %v", err)
	}

	key = types.EncryptionKey{
		KeyType:  etID,
		KeyValue: hash,
	}

	return key, et, nil
}

// GetEncryptedData encrypts the data provided and returns and EncryptedData type.
// Pass a usage value of zero to use the key provided directly rather than deriving one.
func GetEncryptedData(plainBytes []byte, key types.EncryptionKey, usage uint32, kvno int) (types.EncryptedData, error) {
	var ed types.EncryptedData
	et, err := GetEtype(key.KeyType)
	if err != nil {
		return ed, fmt.Errorf("error getting etype: %v", err)
	}
	_, b, err := et.EncryptMessage(key.KeyValue, plainBytes, usage)
	if err != nil {
		return ed, err
	}

	ed = types.EncryptedData{
		EType:  key.KeyType,
		Cipher: b,
		KVNO:   kvno,
	}
	return ed, nil
}

// DecryptEncPart decrypts the EncryptedData.
func DecryptEncPart(ed types.EncryptedData, key types.EncryptionKey, usage uint32) ([]byte, error) {
	return DecryptMessage(ed.Cipher, key, usage)
}

// DecryptMessage decrypts the ciphertext and verifies the integrity.
func DecryptMessage(ciphertext []byte, key types.EncryptionKey, usage uint32) ([]byte, error) {
	et, err := GetEtype(key.KeyType)
	if err != nil {
		return []byte{}, fmt.Errorf("error decrypting: %v", err)
	}
	b, err := et.DecryptMessage(key.KeyValue, ciphertext, usage)
	if err != nil {
		return nil, fmt.Errorf("error decrypting: %v", err)
	}
	return b, nil
}
