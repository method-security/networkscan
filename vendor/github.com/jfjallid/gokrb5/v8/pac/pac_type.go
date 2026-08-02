package pac

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/jfjallid/gokrb5/v8/crypto"
	"github.com/jfjallid/gokrb5/v8/iana/keyusage"
	"github.com/jfjallid/gokrb5/v8/types"
	"github.com/jfjallid/mstypes"
)

const (
	infoTypeKerbValidationInfo     uint32 = 1
	infoTypeCredentials            uint32 = 2
	infoTypePACServerSignatureData uint32 = 6
	infoTypePACKDCSignatureData    uint32 = 7
	infoTypePACClientInfo          uint32 = 10
	infoTypeS4UDelegationInfo      uint32 = 11
	infoTypeUPNDNSInfo             uint32 = 12
	infoTypePACClientClaimsInfo    uint32 = 13
	infoTypePACDeviceInfo          uint32 = 14
	infoTypePACDeviceClaimsInfo    uint32 = 15
	infoTypePacAttributesInfo      uint32 = 17
	infoTypePacRequestorSid        uint32 = 18
)

// PACType implements: https://msdn.microsoft.com/en-us/library/cc237950.aspx
type PACType struct {
	CBuffers           uint32
	Version            uint32
	Buffers            []InfoBuffer
	Data               []byte
	KerbValidationInfo *KerbValidationInfo
	CredentialsInfo    *CredentialsInfo
	ServerChecksum     *SignatureData
	KDCChecksum        *SignatureData
	ClientInfo         *ClientInfo
	S4UDelegationInfo  *S4UDelegationInfo
	UPNDNSInfo         *UPNDNSInfo
	ClientClaimsInfo   *ClientClaimsInfo
	DeviceInfo         *DeviceInfo
	DeviceClaimsInfo   *DeviceClaimsInfo
	PacRequestorSid    *PacRequestorSid
	PacAttributesInfo  *PacAttributesInfo
	ZeroSigData        []byte
}

// InfoBuffer implements the PAC Info Buffer: https://msdn.microsoft.com/en-us/library/cc237954.aspx
type InfoBuffer struct {
	ULType       uint32 // A 32-bit unsigned integer in little-endian format that describes the type of data present in the buffer contained at Offset.
	CBBufferSize uint32 // A 32-bit unsigned integer in little-endian format that contains the size, in bytes, of the buffer in the PAC located at Offset.
	Offset       uint64 // A 64-bit unsigned integer in little-endian format that contains the offset to the beginning of the buffer, in bytes, from the beginning of the PACTYPE structure. The data offset MUST be a multiple of eight. The following sections specify the format of each type of element.
}

func (ib *InfoBuffer) Marshal() (b []byte, err error) {
	w := bytes.NewBuffer([]byte{})
	err = binary.Write(w, binary.LittleEndian, ib.ULType)
	if err != nil {
		return
	}
	err = binary.Write(w, binary.LittleEndian, ib.CBBufferSize)
	if err != nil {
		return
	}
	err = binary.Write(w, binary.LittleEndian, ib.Offset)
	if err != nil {
		return
	}

	return w.Bytes(), nil
}

// Unmarshal bytes into the PACType struct
func (pac *PACType) Unmarshal(b []byte) (err error) {
	pac.Data = b
	zb := make([]byte, len(b), len(b))
	copy(zb, b)
	pac.ZeroSigData = zb
	r := mstypes.NewReader(bytes.NewReader(b))
	pac.CBuffers, err = r.Uint32()
	if err != nil {
		return
	}
	pac.Version, err = r.Uint32()
	if err != nil {
		return
	}
	buf := make([]InfoBuffer, pac.CBuffers, pac.CBuffers)
	for i := range buf {
		buf[i].ULType, err = r.Uint32()
		if err != nil {
			return
		}
		buf[i].CBBufferSize, err = r.Uint32()
		if err != nil {
			return
		}
		buf[i].Offset, err = r.Uint64()
		if err != nil {
			return
		}
	}
	pac.Buffers = buf
	return nil
}

func (pac *PACType) Marshal() (b []byte, err error) {
	if pac.Data == nil {
		err = pac.EncodePACInfoBuffers()
		if err != nil {
			return
		}
	}
	return pac.Data, nil
}

func (pac *PACType) EncodePACInfoBuffers() (err error) {
	pac.Data = make([]byte, 8, 8) // Header
	bufList := make([][]byte, 0)
	pac.Buffers = []InfoBuffer{}

	if pac.KerbValidationInfo != nil {
		buf, err := pac.KerbValidationInfo.Marshal()
		if err != nil {
			return fmt.Errorf("error encoding KerbValidationInfo: %v", err)
		}
		ib := InfoBuffer{
			ULType:       infoTypeKerbValidationInfo,
			CBBufferSize: uint32(len(buf)),
		}
		bufList = append(bufList, buf)
		pac.Buffers = append(pac.Buffers, ib)
	}
	if pac.ClientInfo != nil {
		buf, err := pac.ClientInfo.Marshal()
		if err != nil {
			return fmt.Errorf("error encoding ClientInfo: %v", err)
		}
		ib := InfoBuffer{
			ULType:       infoTypePACClientInfo,
			CBBufferSize: uint32(len(buf)),
		}
		bufList = append(bufList, buf)
		pac.Buffers = append(pac.Buffers, ib)
	}
	if pac.UPNDNSInfo != nil {
		buf, err := pac.UPNDNSInfo.Marshal()
		if err != nil {
			return fmt.Errorf("error encoding UPN_DNSInfo: %v", err)
		}
		ib := InfoBuffer{
			ULType:       infoTypeUPNDNSInfo,
			CBBufferSize: uint32(len(buf)),
		}
		bufList = append(bufList, buf)
		pac.Buffers = append(pac.Buffers, ib)

	}
	if pac.PacRequestorSid != nil {
		buf, err := pac.PacRequestorSid.Marshal()
		if err != nil {
			return fmt.Errorf("error encoding PacRequestorSid: %v", err)
		}
		ib := InfoBuffer{
			ULType:       infoTypePacRequestorSid,
			CBBufferSize: uint32(len(buf)),
		}
		bufList = append(bufList, buf)
		pac.Buffers = append(pac.Buffers, ib)
	}
	if pac.PacAttributesInfo != nil {
		buf, err := pac.PacAttributesInfo.Marshal()
		if err != nil {
			return fmt.Errorf("error encoding PacAttributesInfo: %v", err)
		}
		ib := InfoBuffer{
			ULType:       infoTypePacAttributesInfo,
			CBBufferSize: uint32(len(buf)),
		}
		bufList = append(bufList, buf)
		pac.Buffers = append(pac.Buffers, ib)
	}
	if pac.ServerChecksum != nil {
		buf, err := pac.ServerChecksum.Marshal()
		if err != nil {
			return fmt.Errorf("error encoding ServerChecksum: %v", err)
		}
		ib := InfoBuffer{
			ULType:       infoTypePACServerSignatureData,
			CBBufferSize: uint32(len(buf)),
		}
		bufList = append(bufList, buf)
		pac.Buffers = append(pac.Buffers, ib)
	}
	if pac.KDCChecksum != nil {
		buf, err := pac.KDCChecksum.Marshal()
		if err != nil {
			return fmt.Errorf("error encoding KDCChecksum: %v", err)
		}
		ib := InfoBuffer{
			ULType:       infoTypePACKDCSignatureData,
			CBBufferSize: uint32(len(buf)),
		}
		bufList = append(bufList, buf)
		pac.Buffers = append(pac.Buffers, ib)
	}

	numBuffers := uint64(len(pac.Buffers))
	pac.CBuffers = uint32(numBuffers)
	signatureOffsets := make(map[uint64]uint32)
	serverSignatureSize, err := pac.ServerChecksum.SignatureSize()
	if err != nil {
		return
	}
	kdcSignatureSize, err := pac.KDCChecksum.SignatureSize()
	if err != nil {
		return
	}
	offset := 8 + numBuffers*16
	for i, _ := range pac.Buffers {
		pac.Buffers[i].Offset = offset
		if pac.Buffers[i].ULType == infoTypePACServerSignatureData {
			// Keep track of ServerChecksum buffer offset and size
			signatureOffsets[offset+4] = serverSignatureSize
		} else if pac.Buffers[i].ULType == infoTypePACKDCSignatureData {
			// Keep track of KDCChecksum buffer offset and size
			signatureOffsets[offset+4] = kdcSignatureSize
		}
		ibBuf, err := pac.Buffers[i].Marshal()
		if err != nil {
			return fmt.Errorf("error encoding InfoBuffer: %v", err)
		}
		pac.Data = append(pac.Data, ibBuf...)
		// The actual data buffers must be aligned on 8 byte boundary
		offset = getBlockLength(offset + uint64(pac.Buffers[i].CBBufferSize))
	}
	// Add the actual encoded info buffers last
	for i := range bufList {
		padLen := getPadLength(len(bufList[i]))
		pac.Data = append(pac.Data, append(bufList[i], make([]byte, padLen)...)...)
	}
	binary.LittleEndian.PutUint32(pac.Data[0:4], uint32(numBuffers))
	binary.LittleEndian.PutUint32(pac.Data[4:8], uint32(0)) // pac.Version MUST be 0

	// Keep a separate byte buffer with zero signatures, but otherwise identical
	pac.ZeroSigData = make([]byte, len(pac.Data))
	copy(pac.ZeroSigData, pac.Data)
	for k, v := range signatureOffsets {
		copy(pac.ZeroSigData[k:], make([]byte, v))
	}
	return nil
}

// ProcessPACInfoBuffers processes the PAC Info Buffers.
// https://msdn.microsoft.com/en-us/library/cc237954.aspx
func (pac *PACType) ProcessPACInfoBuffers(key types.EncryptionKey, l *log.Logger, verifyChecksum bool) error {
	for _, buf := range pac.Buffers {
		p := make([]byte, buf.CBBufferSize, buf.CBBufferSize)
		copy(p, pac.Data[int(buf.Offset):int(buf.Offset)+int(buf.CBBufferSize)])
		switch buf.ULType {
		case infoTypeKerbValidationInfo:
			if pac.KerbValidationInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k KerbValidationInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("error processing KerbValidationInfo: %v", err)
			}
			pac.KerbValidationInfo = &k
		case infoTypeCredentials:
			// Currently PAC parsing is only useful on the service side in gokrb5
			// The CredentialsInfo are only useful when gokrb5 has implemented RFC4556 and only applied on the client side.
			// Skipping CredentialsInfo - will be revisited under RFC4556 implementation.
			continue
			//if pac.CredentialsInfo != nil {
			//	//Must ignore subsequent buffers of this type
			//	continue
			//}
			//var k CredentialsInfo
			//err := k.Unmarshal(p, key) // The encryption key used is the AS reply key only available to the client.
			//if err != nil {
			//	return fmt.Errorf("error processing CredentialsInfo: %v", err)
			//}
			//pac.CredentialsInfo = &k
		case infoTypePACServerSignatureData:
			if pac.ServerChecksum != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k SignatureData
			zb, err := k.Unmarshal(p)
			copy(pac.ZeroSigData[int(buf.Offset):int(buf.Offset)+int(buf.CBBufferSize)], zb)
			if err != nil {
				return fmt.Errorf("error processing ServerChecksum: %v", err)
			}
			pac.ServerChecksum = &k
		case infoTypePACKDCSignatureData:
			if pac.KDCChecksum != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k SignatureData
			zb, err := k.Unmarshal(p)
			copy(pac.ZeroSigData[int(buf.Offset):int(buf.Offset)+int(buf.CBBufferSize)], zb)
			if err != nil {
				return fmt.Errorf("error processing KDCChecksum: %v", err)
			}
			pac.KDCChecksum = &k
		case infoTypePACClientInfo:
			if pac.ClientInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k ClientInfo
			err := k.Unmarshal(p)
			if err != nil {
				return fmt.Errorf("error processing ClientInfo: %v", err)
			}
			pac.ClientInfo = &k
		case infoTypeS4UDelegationInfo:
			if pac.S4UDelegationInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k S4UDelegationInfo
			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process S4U_DelegationInfo: %v", err)
				continue
			}
			pac.S4UDelegationInfo = &k
		case infoTypeUPNDNSInfo:
			if pac.UPNDNSInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k UPNDNSInfo
			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process UPN_DNSInfo: %v", err)
				continue
			}
			pac.UPNDNSInfo = &k
		case infoTypePACClientClaimsInfo:
			if pac.ClientClaimsInfo != nil || len(p) < 1 {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k ClientClaimsInfo
			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process ClientClaimsInfo: %v", err)
				continue
			}
			pac.ClientClaimsInfo = &k
		case infoTypePACDeviceInfo:
			if pac.DeviceInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k DeviceInfo
			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process DeviceInfo: %v", err)
				continue
			}
			pac.DeviceInfo = &k
		case infoTypePACDeviceClaimsInfo:
			if pac.DeviceClaimsInfo != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k DeviceClaimsInfo
			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process DeviceClaimsInfo: %v", err)
				continue
			}
			pac.DeviceClaimsInfo = &k
		case infoTypePacRequestorSid:
			if pac.PacRequestorSid != nil {
				//Must ignore subsequent buffers of this type
				continue
			}
			var k PacRequestorSid
			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process PacRequestorSid: %v\n", err)
				continue
			}
			pac.PacRequestorSid = &k
		case infoTypePacAttributesInfo:
			if pac.PacAttributesInfo != nil {
				//Ignore subsequent buffers of this type
				continue
			}
			var k PacAttributesInfo
			err := k.Unmarshal(p)
			if err != nil {
				l.Printf("could not process PacAttributesInfo: %v\n", err)
				continue
			}
			pac.PacAttributesInfo = &k
		}
	}

	if verifyChecksum {
		if ok, err := pac.verify(key); !ok {
			return err
		}
	}

	return nil
}

// ProcessCredentialsInfo decrypts the PAC_CREDENTIAL_INFO buffer using the provided AS reply key.
// This is used for UnPAC-the-hash: extracting NT hashes from PKINIT U2U tickets.
// The asReplyKey is the DH-derived key from PKINIT, NOT the TGT session key.
// Returns nil if no credentials buffer is present in the PAC.
func (pac *PACType) ProcessCredentialsInfo(asReplyKey types.EncryptionKey) error {
	for _, buf := range pac.Buffers {
		if buf.ULType != infoTypeCredentials {
			continue
		}
		if pac.CredentialsInfo != nil {
			// Must ignore subsequent buffers of this type
			continue
		}
		p := make([]byte, buf.CBBufferSize)
		copy(p, pac.Data[int(buf.Offset):int(buf.Offset)+int(buf.CBBufferSize)])
		var k CredentialsInfo
		err := k.Unmarshal(p, asReplyKey)
		if err != nil {
			return fmt.Errorf("error processing CredentialsInfo: %v", err)
		}
		pac.CredentialsInfo = &k
	}
	return nil
}

func (pac *PACType) verify(key types.EncryptionKey) (bool, error) {
	if pac.KerbValidationInfo == nil {
		return false, errors.New("PAC Info Buffers does not contain a KerbValidationInfo")
	}
	if pac.ServerChecksum == nil {
		return false, errors.New("PAC Info Buffers does not contain a ServerChecksum")
	}
	if pac.KDCChecksum == nil {
		return false, errors.New("PAC Info Buffers does not contain a KDCChecksum")
	}
	if pac.ClientInfo == nil {
		return false, errors.New("PAC Info Buffers does not contain a ClientInfo")
	}
	etype, err := crypto.GetChksumEtype(int32(pac.ServerChecksum.SignatureType))
	if err != nil {
		return false, err
	}
	if ok := etype.VerifyChecksum(key.KeyValue,
		pac.ZeroSigData,
		pac.ServerChecksum.Signature,
		keyusage.KERB_NON_KERB_CKSUM_SALT); !ok {
		return false, errors.New("PAC service checksum verification failed")
	}

	return true, nil
}

// Align on 8 byte boundary
func getPadLength(dataLength int) int {
	return (((dataLength + 7) / 8) * 8) - dataLength
}

// Align on 8 byte boundary
func getBlockLength(dataLength uint64) uint64 {
	return (((dataLength + 7) / 8) * 8)
}
