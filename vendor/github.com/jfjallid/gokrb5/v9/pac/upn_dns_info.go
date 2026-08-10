package pac

import (
	"bytes"
	"encoding/binary"

	"github.com/jfjallid/mstypes"
)

// UPNDNSInfo implements https://msdn.microsoft.com/en-us/library/dd240468.aspx
type UPNDNSInfo struct {
	UPNLength           uint16 // An unsigned 16-bit integer in little-endian format that specifies the length, in bytes, of the UPN field.
	UPNOffset           uint16 // An unsigned 16-bit integer in little-endian format that contains the offset to the beginning of the buffer, in bytes, from the beginning of the UPN_DNS_INFO structure.
	DNSDomainNameLength uint16
	DNSDomainNameOffset uint16
	Flags               uint32
	SamNameLength       uint16
	SamNameOffset       uint16
	SidLength           uint16
	SidOffset           uint16
	UPN                 string
	DNSDomain           string
	SamName             string
	Sid                 *mstypes.RPCSID
}

const (
	upnNoUPNAttr = 31 // The user account object does not have the userPrincipalName attribute ([MS-ADA3] section 2.349) set. A UPN constructed by concatenating the user name with the DNS domain name of the account domain is provided.
)

// Unmarshal bytes into the UPN_DNSInfo struct
func (k *UPNDNSInfo) Unmarshal(b []byte) (err error) {
	//The UPN_DNS_INFO structure is a simple structure that is not NDR-encoded.
	r := mstypes.NewReader(bytes.NewReader(b))
	k.UPNLength, err = r.Uint16()
	if err != nil {
		return
	}
	k.UPNOffset, err = r.Uint16()
	if err != nil {
		return
	}
	k.DNSDomainNameLength, err = r.Uint16()
	if err != nil {
		return
	}
	k.DNSDomainNameOffset, err = r.Uint16()
	if err != nil {
		return
	}
	k.Flags, err = r.Uint32()
	if err != nil {
		return
	}
	if (k.Flags & 0x2) == 0x2 {
		// Structure contains Sid and SamName
		k.SamNameLength, err = r.Uint16()
		if err != nil {
			return
		}
		k.SamNameOffset, err = r.Uint16()
		if err != nil {
			return
		}
		k.SidLength, err = r.Uint16()
		if err != nil {
			return
		}
		k.SidOffset, err = r.Uint16()
		if err != nil {
			return
		}

		samb := mstypes.NewReader(bytes.NewReader(b[k.SamNameOffset : k.SamNameOffset+k.SamNameLength]))
		sam := make([]rune, k.SamNameLength/2, k.SamNameLength/2)
		for i := 0; i < len(sam); i++ {
			var r uint16
			r, err = samb.Uint16()
			if err != nil {
				return
			}
			sam[i] = rune(r)
		}
		k.SamName = string(sam)
		var sid mstypes.RPCSID
		sidb := mstypes.NewReader(bytes.NewReader(b[k.SidOffset : k.SidOffset+k.SidLength]))
		sid, err = sidb.RPCSid()
		if err != nil {
			return
		}
		k.Sid = &sid
	}

	ub := mstypes.NewReader(bytes.NewReader(b[k.UPNOffset : k.UPNOffset+k.UPNLength]))
	db := mstypes.NewReader(bytes.NewReader(b[k.DNSDomainNameOffset : k.DNSDomainNameOffset+k.DNSDomainNameLength]))

	u := make([]rune, k.UPNLength/2, k.UPNLength/2)
	for i := 0; i < len(u); i++ {
		var r uint16
		r, err = ub.Uint16()
		if err != nil {
			return
		}
		u[i] = rune(r)
	}
	k.UPN = string(u)
	d := make([]rune, k.DNSDomainNameLength/2, k.DNSDomainNameLength/2)
	for i := 0; i < len(d); i++ {
		var r uint16
		r, err = db.Uint16()
		if err != nil {
			return
		}
		d[i] = rune(r)
	}
	k.DNSDomain = string(d)

	return
}

func (k *UPNDNSInfo) Marshal() (buf []byte, err error) {
	w := bytes.NewBuffer(buf)
	var includeSid bool
	upnBytes := toUnicode(k.UPN)
	dnsBytes := toUnicode(k.DNSDomain)
	var samBytes, sidBytes []byte
	upnLen := uint16(len(upnBytes))
	dnsLen := uint16(len(dnsBytes))
	offset := uint16(16) // Should be aligned on 8 byte boundary?
	if k.Sid != nil && k.SamName != "" {
		//if (k.Flags & 0x2) == 0x2 {
		// Sid and SPN included
		includeSid = true
		k.Flags |= 0x2
		offset = 24
		//err = fmt.Errorf("Marshal of UPN_DNSInfo with SAM an SID included has not been implemented")
		//return
	}

	err = binary.Write(w, binary.LittleEndian, upnLen) // any padding to include?
	if err != nil {
		return
	}
	err = binary.Write(w, binary.LittleEndian, offset)
	if err != nil {
		return
	}
	offset = uint16(getBlockLength(uint64(offset + upnLen)))
	err = binary.Write(w, binary.LittleEndian, dnsLen) // any padding to include?
	if err != nil {
		return
	}
	err = binary.Write(w, binary.LittleEndian, offset)
	if err != nil {
		return
	}
	offset = uint16(getBlockLength(uint64(offset + dnsLen)))

	err = binary.Write(w, binary.LittleEndian, k.Flags)
	if err != nil {
		return
	}

	if includeSid {
		samBytes = toUnicode(k.SamName)
		samLen := uint16(len(samBytes))

		err = binary.Write(w, binary.LittleEndian, samLen) // any padding to include?
		if err != nil {
			return
		}
		err = binary.Write(w, binary.LittleEndian, offset)
		if err != nil {
			return
		}
		offset = uint16(getBlockLength(uint64(offset + samLen)))

		w2 := bytes.NewBuffer([]byte{})
		err = k.Sid.ToWriter(w2)
		if err != nil {
			return
		}
		sidLen := uint16(len(w2.Bytes()))
		err = binary.Write(w, binary.LittleEndian, sidLen) // any padding to include?
		if err != nil {
			return
		}
		err = binary.Write(w, binary.LittleEndian, offset)
		if err != nil {
			return
		}
		offset = uint16(getBlockLength(uint64(offset + sidLen)))
		sidBytes = w2.Bytes()
	}

	// Handle padding/alignment
	err = binary.Write(w, binary.LittleEndian, make([]byte, getPadLength(w.Len())))
	if err != nil {
		return
	}

	err = binary.Write(w, binary.LittleEndian, upnBytes)
	if err != nil {
		return
	}

	// Handle padding/alignment
	err = binary.Write(w, binary.LittleEndian, make([]byte, getPadLength(w.Len())))
	if err != nil {
		return
	}
	err = binary.Write(w, binary.LittleEndian, dnsBytes)
	if err != nil {
		return
	}

	if includeSid {
		// Handle padding/alignment
		err = binary.Write(w, binary.LittleEndian, make([]byte, getPadLength(w.Len())))
		if err != nil {
			return
		}
		err = binary.Write(w, binary.LittleEndian, samBytes)
		if err != nil {
			return
		}
		// Handle padding/alignment
		err = binary.Write(w, binary.LittleEndian, make([]byte, getPadLength(w.Len())))
		if err != nil {
			return
		}
		err = binary.Write(w, binary.LittleEndian, sidBytes)
		if err != nil {
			return
		}
	}

	return w.Bytes(), nil
}
