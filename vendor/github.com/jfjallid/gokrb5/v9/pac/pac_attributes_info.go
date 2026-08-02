package pac

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/mstypes"
)

// PacAttributesInfo implements MS-PAC Section 2.14 PAC_ATTRIBUTES_INFO
// Not exactly according to specification with uint32 instead of []uint32 for Flags.
// But there are only 2 byts defined in the specification so should never be more than
// one uint32 anyways.
type PacAttributesInfo struct {
	FlagsLength uint32 // An unsigned 32-bit integer in little-endian format that describes the length, in bits, of the Flags field as the count of flag bits not including padding.
	Flags       uint32 /* An array of 32-bit unsigned integers in little-endian format that contains flag bits describing the PacAttributesInfo
	Each 32-bit unsigned integer contains up to 32 defined bits.
	All bits are flag bits padded to a unit multiple of 32 bits of storage (a 32-bit integer).
	Undefined padding bits are zero and MUST be ignored on receipt. The following bits are currently defined.
	*/
}

// Unmarshal bytes into the PacAttributesInfo struct
func (k *PacAttributesInfo) Unmarshal(b []byte) (err error) {
	if len(b) == 0 {
		return
	}
	r := mstypes.NewReader(bytes.NewReader(b))
	k.FlagsLength, err = r.Uint32()
	if err != nil {
		err = fmt.Errorf("error unmarshaling PacAttributesInfo FlagsLength: %v", err)
	}
	if k.FlagsLength > 0 {
		k.Flags, err = r.Uint32()
		if err != nil {
			err = fmt.Errorf("error unmarshaling PacAttributesInfo Flags: %v", err)
		}
	}

	return
}

func (k *PacAttributesInfo) Marshal() (buf []byte, err error) {
	w := bytes.NewBuffer(buf)
	err = binary.Write(w, binary.LittleEndian, k.FlagsLength)
	if err != nil {
		err = fmt.Errorf("error marshaling PacAttributesInfo: %v", err)
	}
	err = binary.Write(w, binary.LittleEndian, k.Flags)
	if err != nil {
		err = fmt.Errorf("error marshaling PacAttributesInfo: %v", err)
	}

	return w.Bytes(), nil
}
