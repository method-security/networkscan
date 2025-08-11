package mstypes

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// RPCSID implements https://msdn.microsoft.com/en-us/library/cc230364.aspx
type RPCSID struct {
	Revision            uint8    // An 8-bit unsigned integer that specifies the revision level of the SID. This value MUST be set to 0x01.
	SubAuthorityCount   uint8    // An 8-bit unsigned integer that specifies the number of elements in the SubAuthority array. The maximum number of elements allowed is 15.
	IdentifierAuthority [6]byte  // An RPC_SID_IDENTIFIER_AUTHORITY structure that indicates the authority under which the SID was created. It describes the entity that created the SID. The Identifier Authority value {0,0,0,0,0,5} denotes SIDs created by the NT SID authority.
	SubAuthority        []uint32 `ndr:"conformant"` // A variable length array of unsigned 32-bit integers that uniquely identifies a principal relative to the IdentifierAuthority. Its length is determined by SubAuthorityCount.
}

// String returns the string representation of the RPC_SID.
func (s *RPCSID) String() string {
	var strb strings.Builder
	strb.WriteString("S-1-")

	b := append(make([]byte, 2, 2), s.IdentifierAuthority[:]...)
	// For a strange reason this is read big endian: https://msdn.microsoft.com/en-us/library/dd302645.aspx
	i := binary.BigEndian.Uint64(b)
	if i > math.MaxUint32 {
		fmt.Fprintf(&strb, "0x%s", hex.EncodeToString(s.IdentifierAuthority[:]))
	} else {
		fmt.Fprintf(&strb, "%d", i)
	}
	for _, sub := range s.SubAuthority {
		fmt.Fprintf(&strb, "-%d", sub)
	}
	return strb.String()
}

func (s *RPCSID) ToWriter(w io.Writer) (err error) {
	err = binary.Write(w, binary.LittleEndian, s.Revision)
	if err != nil {
		return
	}

	err = binary.Write(w, binary.LittleEndian, s.SubAuthorityCount)
	if err != nil {
		return
	}
	err = binary.Write(w, binary.LittleEndian, s.IdentifierAuthority)
	if err != nil {
		return
	}
	for i := 0; i < int(s.SubAuthorityCount); i++ {
		err = binary.Write(w, binary.LittleEndian, s.SubAuthority[i])
		if err != nil {
			return
		}
	}
	return
}

func ConvertStrToSID(s string) (sid *RPCSID, err error) {
	sid = &RPCSID{}
	parts := strings.Split(s, "-")
	if len(parts) < 4 {
		err = fmt.Errorf("Invalid SID representation")
		return
	}
	rev, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("could't convert revision to string: %s", err.Error())
	}
	sid.Revision = byte(rev)
	auth, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("could't convert authority to string: %s", err.Error())
	}
	authBuf := make([]byte, 2, 6)
	authBuf = binary.BigEndian.AppendUint32(authBuf, uint32(auth))
	copy(sid.IdentifierAuthority[:], authBuf)
	subCount := byte(0)
	subAuths := make([]uint32, 0)
	for _, part := range parts[3:] {
		subA, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("could't convert subauthority to string: %s", err.Error())
		}
		subAuths = append(subAuths, uint32(subA))
		subCount += 1
	}
	sid.SubAuthority = subAuths
	sid.SubAuthorityCount = subCount
	return
}
