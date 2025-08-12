package ndr

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

/*
Serialization Version 1
https://msdn.microsoft.com/en-us/library/cc243563.aspx

Common Header - https://msdn.microsoft.com/en-us/library/cc243890.aspx
8 bytes in total:
- First byte - Version: Must equal 1
- Second byte -  1st 4 bits: Endianess (0=Big; 1=Little); 2nd 4 bits: Character Encoding (0=ASCII; 1=EBCDIC)
- 3rd - Floating point representation (This does not seem to be the case in examples for Microsoft test sources)
- 4th - Common Header Length: Must equal 8
- 5th - 8th - Filler: MUST be set to 0xcccccccc on marshaling, and SHOULD be ignored during unmarshaling.

Private Header - https://msdn.microsoft.com/en-us/library/cc243919.aspx
8 bytes in total:
- First 4 bytes - Indicates the length of a serialized top-level type in the octet stream. It MUST include the padding length and exclude the header itself.
- Second 4 bytes - Filler: MUST be set to 0 (zero) during marshaling, and SHOULD be ignored during unmarshaling.
*/

const (
	protocolVersion   uint8  = 1
	commonHeaderBytes uint16 = 8
	bigEndian                = 0
	littleEndian             = 1
	ascii             uint8  = 0
	ebcdic            uint8  = 1
	ieee              uint8  = 0
	vax               uint8  = 1
	cray              uint8  = 2
	ibm               uint8  = 3
)

// CommonHeader implements the NDR common header: https://msdn.microsoft.com/en-us/library/cc243889.aspx
type CommonHeader struct {
	Version             uint8
	Endianness          binary.ByteOrder
	CharacterEncoding   uint8
	FloatRepresentation uint8
	HeaderLength        uint16
	Filler              []byte
}

// PrivateHeader implements the NDR private header: https://msdn.microsoft.com/en-us/library/cc243919.aspx
type PrivateHeader struct {
	ObjectBufferLength uint32
	Filler             []byte
}

func (dec *Decoder) readCommonHeader() error {
	// Version
	vb, err := dec.r.ReadByte()
	if err != nil {
		return Malformed{EText: "could not read first byte of common header for version"}
	}
	dec.ch.Version = uint8(vb)
	switch dec.ch.Version {
	case 1:
		return dec.readCommonHeaderV1()
	case 2:
		return dec.readCommonHeaderV2()
	default:
		return Malformed{EText: fmt.Sprintf("byte stream does not indicate a RPC Type serialization of version 1 or 2 but instead: %v", dec.ch.Version)}
	}
}

func (dec *Decoder) readCommonHeaderV1() error {
	//// Version
	//vb, err := dec.r.ReadByte()
	//if err != nil {
	//	return Malformed{EText: "could not read first byte of common header for version"}
	//}
	//dec.ch.Version = uint8(vb)
	//if dec.ch.Version != protocolVersion {
	//	return Malformed{EText: fmt.Sprintf("byte stream does not indicate a RPC Type serialization of version %v but instead: %v", protocolVersion, dec.ch.Version)}
	//}
	// Read Endianness & Character Encoding
	eb, err := dec.r.ReadByte()
	if err != nil {
		return Malformed{EText: "could not read second byte of common header for endianness"}
	}
	endian := int(eb >> 4 & 0xF)
	if endian != 0 && endian != 1 {
		return Malformed{EText: "common header does not indicate a valid endianness"}
	}
	//dec.ch.CharacterEncoding = uint8(vb & 0xF)
	dec.ch.CharacterEncoding = uint8(dec.ch.Version & 0xF)
	if dec.ch.CharacterEncoding != 0 && dec.ch.CharacterEncoding != 1 {
		return Malformed{EText: "common header does not indicate a valid character encoding"}
	}
	switch endian {
	case littleEndian:
		dec.ch.Endianness = binary.LittleEndian
	case bigEndian:
		dec.ch.Endianness = binary.BigEndian
	}
	// Common header length
	lb, err := dec.readBytes(2)
	if err != nil {
		return Malformed{EText: fmt.Sprintf("could not read common header length: %v", err)}
	}
	dec.ch.HeaderLength = dec.ch.Endianness.Uint16(lb)
	if dec.ch.HeaderLength != commonHeaderBytes {
		return Malformed{EText: "common header does not indicate a valid length"}
	}
	// Filler bytes
	dec.ch.Filler, err = dec.readBytes(4)
	if err != nil {
		return Malformed{EText: fmt.Sprintf("could not read common header filler: %v", err)}
	}
	return nil
}

func (dec *Decoder) readCommonHeaderV2() error {
	// Read endianness byte
	eb, err := dec.r.ReadByte()
	if err != nil {
		return Malformed{EText: "could not read second byte of common header for endianness"}
	}
	//Endianness (1 byte): MUST be set to little-endian (0x10).
	if eb != 0x10 { // MUST be LittleEndian
		return Malformed{EText: fmt.Sprintf("common header v2 for endianness does NOT specify LittleEndian 0x10, but %x", eb)}
	}
	dec.ch.Endianness = binary.LittleEndian
	// Common header length
	lb, err := dec.readBytes(2)
	if err != nil {
		return Malformed{EText: fmt.Sprintf("could not read common header v2 length: %v", err)}
	}
	dec.ch.HeaderLength = dec.ch.Endianness.Uint16(lb)
	// CommonHeaderLength (2 bytes): Indicates the length in bytes of the common header. MUST be 0x40.
	if dec.ch.HeaderLength != 0x40 {
		//return Malformed{EText: "common header v2 does not indicate a valid length of 0x40"}
		return Malformed{EText: fmt.Sprintf("common header v2 does not indicate a valid length of 0x40, but %x", dec.ch.HeaderLength)}
	}

	// endianInfo (4 bytes): Reserved field. MUST be set to 0XCCCCCCCC during marshaling, and SHOULD be ignored during unmarshaling.
	_, err = dec.readBytes(4)
	if err != nil {
		return Malformed{EText: fmt.Sprintf("could not read common header v2 endianInfo: %v", err)}
	}
	// Reserved (16 bytes): Reserved fields. MUST be set to 0XCCCCCCCC during marshaling and SHOULD be ignored during unmarshaling.
	_, err = dec.readBytes(16)
	if err != nil {
		return Malformed{EText: fmt.Sprintf("could not read common header v2 reserved bytes: %v", err)}
	}

	// TransferSyntax (20 bytes): RPC transfer syntax identifier used to encode data in the octet stream. It MUST use RPC_SYNTAX_IDENTIFIER format, as specified in section 2.2.2.7. It MUST be either the NDR transfer syntax identifier or the NDR64 transfer syntax identifier.
	tsb, err := dec.readBytes(20)
	if err != nil {
		return Malformed{EText: fmt.Sprintf("could not read common header v2 TransferSyntax bytes: %v", err)}
	}

	ndrUuid, err := uuid_to_bin("8a885d04-1ceb-11c9-9fe8-08002b104860") // NDR Transfer Syntax version 2.0
	if err != nil {
		return fmt.Errorf("Failed to convert NDRUuid string to bytes")
	}
	// Expect NDR and not NDR64
	if !bytes.Equal(tsb, ndrUuid) {
		return Malformed{EText: fmt.Sprintf("common header v2 invalid TransferSyntax bytes: %x", tsb)}
	}

	//InterfaceID (20 bytes): Interface identifier, as specified in the IDL file. It MUST use the interface identifier format, as specified in [C706] section 3.1.9. Implementations MAY ignore the value of this field.<58>
	_, err = dec.readBytes(20)
	if err != nil {
		return Malformed{EText: fmt.Sprintf("could not read common header v2 InterfaceID bytes: %v", err)}
	}
	return nil
}

func (dec *Decoder) readPrivateHeader() error {
	if dec.ch.Version == 1 {
		return dec.readPrivateHeaderV1()
	} else {
		return dec.readPrivateHeaderV2()
	}
}

func (dec *Decoder) readPrivateHeaderV1() error {
	// The next 8 bytes after the common header comprise the RPC type marshalling private header for constructed types.
	err := binary.Read(dec.r, dec.ch.Endianness, &dec.ph.ObjectBufferLength)
	if err != nil {
		return Malformed{EText: "could not read private header object buffer length"}
	}
	if dec.ph.ObjectBufferLength%8 != 0 {
		return Malformed{EText: "object buffer length not a multiple of 8"}
	}
	// Filler bytes
	dec.ph.Filler, err = dec.readBytes(4)
	if err != nil {
		return Malformed{EText: fmt.Sprintf("could not read private header filler: %v", err)}
	}
	return nil
}

func (dec *Decoder) readPrivateHeaderV2() error {
	// The next 8 bytes after the common header comprise the RPC type marshalling private header for constructed types.
	err := binary.Read(dec.r, dec.ch.Endianness, &dec.ph.ObjectBufferLength)
	if err != nil {
		return Malformed{EText: "could not read private header object buffer length"}
	}
	if dec.ph.ObjectBufferLength%8 != 0 {
		return Malformed{EText: "object buffer length not a multiple of 8"}
	}
	// Filler bytes
	dec.ph.Filler, err = dec.readBytes(12)
	if err != nil {
		return Malformed{EText: fmt.Sprintf("could not read private header filler: %v", err)}
	}
	return nil
}

func (enc *Encoder) writeCommonHeader(w *bytes.Buffer) (err error) {
	//Common header
	binary.Write(w, binary.LittleEndian, uint8(1))
	binary.Write(w, binary.LittleEndian, uint8(0x10))
	binary.Write(w, binary.LittleEndian, uint16(0x0008))
	binary.Write(w, binary.LittleEndian, uint32(0xCCCCCCCC))
	return
}

func (enc *Encoder) writePrivateHeader(w *bytes.Buffer) (err error) {
	//Private header
	bufLen := uint32(enc.w.Len())
	bufferSize := ((bufLen + 7) / 8) * 8
	padd := bufferSize - bufLen
	binary.Write(enc.w, binary.LittleEndian, make([]byte, padd))

	binary.Write(w, binary.LittleEndian, bufferSize)
	binary.Write(w, binary.LittleEndian, uint32(0x00000000))
	return
}
