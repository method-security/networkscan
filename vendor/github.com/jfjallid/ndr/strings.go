package ndr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"unicode/utf16"
)

const (
	subStringArrayTag   = `ndr:"varying,X-subStringArray"`
	subStringArrayValue = "X-subStringArray"
)

func uint16SliceToString(a []uint16) string {
	s := make([]rune, len(a), len(a))
	for i := range s {
		s[i] = rune(a[i])
	}
	if len(s) > 0 {
		// Remove any null terminator
		if s[len(s)-1] == rune(0) {
			s = s[:len(s)-1]
		}
	}
	return string(s)
}

func (dec *Decoder) readVaryingString(def *[]deferedPtr) (string, error) {
	a := new([]uint16)
	v := reflect.ValueOf(a)
	var t reflect.StructTag
	err := dec.fillUniDimensionalVaryingArray(v.Elem(), t, def)
	if err != nil {
		return "", err
	}
	s := uint16SliceToString(*a)
	return s, nil
}

func (dec *Decoder) readConformantVaryingString(def *[]deferedPtr) (string, error) {
	a := new([]uint16)
	v := reflect.ValueOf(a)
	var t reflect.StructTag
	err := dec.fillUniDimensionalConformantVaryingArray(v.Elem(), t, def)
	if err != nil {
		return "", err
	}
	s := uint16SliceToString(*a)
	//fmt.Printf("Read string: %q\n", s)
	return s, nil
}

func (dec *Decoder) readStringsArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	d, _ := sliceDimensions(v.Type())
	ndrTag := parseTags(tag)
	var m []int
	//var ms int
	if ndrTag.HasValue(TagConformant) {
		for i := 0; i < d; i++ {
			m = append(m, int(dec.precedingMax()))
		}
		//common max size
		_ = dec.precedingMax()
		//ms = int(n)
	}
	tag = reflect.StructTag(subStringArrayTag)
	err := dec.fillVaryingArray(v, tag, def)
	if err != nil {
		return fmt.Errorf("could not read string array: %v", err)
	}
	return nil
}

func (enc *Encoder) ToUnicode(input string) []byte {
	codePoints := utf16.Encode([]rune(input))
	b := bytes.Buffer{}
	binary.Write(&b, enc.ch.Endianness, &codePoints)
	return b.Bytes()
}

func (enc *Encoder) writeConformantVaryingString(s string) error {
	var actualLen uint32
	var unc []byte
	//if s == "" {
	//	s = "\x00"
	//} else {
	//	if !strings.HasSuffix(s, "\x00") {
	//		// Add null byte
	//		s += "\x00"
	//	}
	//}
	unc = enc.ToUnicode(s)
	actualLen = uint32(len(unc) / 2)

	//NOTE according to NDR, strings should always be null terminated
	// and both maxCount and actualLen should include the null terminator
	//if s != "" {
	//	unc = enc.ToUnicode(s)
	//	maxLen = uint32(len(unc)/2)
	//	if s[len(s)-1] == '\x00' {
	//		actualLen = maxLen - 1 // without the null terminator
	//	} else {
	//		actualLen = maxLen
	//	}
	//}
	enc.ensureAlignment(SizeUint32)
	binary.Write(enc.w, enc.ch.Endianness, uint32(0)) // offset
	binary.Write(enc.w, enc.ch.Endianness, actualLen)
	binary.Write(enc.w, enc.ch.Endianness, unc)
	enc.ensureAlignment(SizeUint32) // Need to align at 4 byte boundary even if uint16 comes after
	return nil
}

//func (enc *Encoder) writeVaryingString(s string, def *[]deferedPtr) (error) {
//	a := new([]uint16)
//	v := reflect.ValueOf(a)
//	var t reflect.StructTag
//	err := enc.writeUniDimensionalVaryingArray(v.Elem(), t, def)
//	if err != nil {
//		return "", err
//	}
//	s := uint16SliceToString(*a)
//	return s, nil
//}
