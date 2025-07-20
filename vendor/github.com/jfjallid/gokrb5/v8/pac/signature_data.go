package pac

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/gokrb5/v8/iana/chksumtype"
	"github.com/jfjallid/mstypes"
)

/*
https://msdn.microsoft.com/en-us/library/cc237955.aspx

The Key Usage Value MUST be KERB_NON_KERB_CKSUM_SALT (17) [MS-KILE] (section 3.1.5.9).

Server Signature (SignatureType = 0x00000006)
https://msdn.microsoft.com/en-us/library/cc237957.aspx

KDC Signature (SignatureType = 0x00000007)
https://msdn.microsoft.com/en-us/library/dd357117.aspx
*/

// SignatureData implements https://msdn.microsoft.com/en-us/library/cc237955.aspx
type SignatureData struct {
	SignatureType  uint32 // A 32-bit unsigned integer value in little-endian format that defines the cryptographic system used to calculate the checksum. This MUST be one of the following checksum types: KERB_CHECKSUM_HMAC_MD5 (signature size = 16), HMAC_SHA1_96_AES128 (signature size = 12), HMAC_SHA1_96_AES256 (signature size = 12).
	Signature      []byte // Size depends on the type. See comment above.
	RODCIdentifier uint16 // A 16-bit unsigned integer value in little-endian format that contains the first 16 bits of the key version number ([MS-KILE] section 3.1.5.8) when the KDC is an RODC. When the KDC is not an RODC, this field does not exist.
}

// Unmarshal bytes into the SignatureData struct
func (k *SignatureData) Unmarshal(b []byte) (rb []byte, err error) {
	r := mstypes.NewReader(bytes.NewReader(b))

	k.SignatureType, err = r.Uint32()
	if err != nil {
		return
	}

	var c int
	switch k.SignatureType {
	case chksumtype.KERB_CHECKSUM_HMAC_MD5_UNSIGNED:
		c = 16
	case uint32(chksumtype.HMAC_SHA1_96_AES128):
		c = 12
	case uint32(chksumtype.HMAC_SHA1_96_AES256):
		c = 12
	case uint32(chksumtype.HMAC_SHA256_128_AES128):
		c = 16
	case uint32(chksumtype.HMAC_SHA384_192_AES256):
		c = 24
	}
	k.Signature, err = r.ReadBytes(c)
	if err != nil {
		return
	}

	// When the KDC is not an Read Only Domain Controller (RODC), this field does not exist.
	if len(b) >= 4+c+2 {
		k.RODCIdentifier, err = r.Uint16()
		if err != nil {
			return
		}
	}

	// Create bytes with zeroed signature needed for checksum verification
	rb = make([]byte, len(b), len(b))
	copy(rb, b)
	z := make([]byte, len(b), len(b))
	copy(rb[4:4+c], z)

	return
}

func (k *SignatureData) Marshal() (b []byte, err error) {
	w := bytes.NewBuffer([]byte{})
	err = binary.Write(w, binary.LittleEndian, k.SignatureType)
	if err != nil {
		return
	}
	err = binary.Write(w, binary.LittleEndian, k.Signature)
	if err != nil {
		return
	}
	if k.RODCIdentifier != 0 {
		err = binary.Write(w, binary.LittleEndian, k.RODCIdentifier)
		if err != nil {
			return
		}
	}
	return w.Bytes(), nil
}

func (k *SignatureData) SignatureSize() (s uint32, err error) {
	switch k.SignatureType {
	case chksumtype.KERB_CHECKSUM_HMAC_MD5_UNSIGNED:
		s = 16
	case uint32(chksumtype.HMAC_SHA1_96_AES128):
		s = 12
	case uint32(chksumtype.HMAC_SHA1_96_AES256):
		s = 12
	case uint32(chksumtype.HMAC_SHA256_128_AES128):
		s = 16
	case uint32(chksumtype.HMAC_SHA384_192_AES256):
		s = 24
	default:
		err = fmt.Errorf("Could not determine size of invalid SignatureType: %d", k.SignatureType)
	}
	return
}
