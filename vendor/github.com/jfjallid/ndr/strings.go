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

func (enc *Encoder) writeStringsArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	// Conformant max values (array dimensions + common string max) are already
	// written by process()/conformantScan(). Just write the varying array with
	// subStringArrayTag so each element is encoded as a varying string.
	tag = reflect.StructTag(subStringArrayTag)
	err := enc.writeVaryingArray(v, tag, def)
	if err != nil {
		return fmt.Errorf("could not write string array: %v", err)
	}
	return nil
}

// stringArrayCommonMax walks a (possibly multi-dimensional) slice/array of
// strings and returns the max UTF-16 code-unit length among all strings, plus
// one for the null terminator unless skipNull is true. Used by the encoder to
// emit a valid conformant max_count (>= actual_count) for the common string
// dimension of a conformant string array.
func stringArrayCommonMax(v reflect.Value, skipNull bool) uint32 {
	var walk func(rv reflect.Value) uint32
	walk = func(rv reflect.Value) uint32 {
		switch rv.Kind() {
		case reflect.Slice, reflect.Array:
			var m uint32
			for i := 0; i < rv.Len(); i++ {
				if x := walk(rv.Index(i)); x > m {
					m = x
				}
			}
			return m
		case reflect.String:
			l := uint32(len(utf16.Encode([]rune(rv.String()))))
			if !skipNull {
				l++
			}
			return l
		}
		return 0
	}
	return walk(v)
}

func (enc *Encoder) ToUnicode(input string) []byte {
	codePoints := utf16.Encode([]rune(input))
	b := bytes.Buffer{}
	binary.Write(&b, enc.ch.Endianness, &codePoints)
	return b.Bytes()
}

// writeVaryingString writes the inline varying-string representation:
// offset (0) + actual_count + UTF-16LE data + 4-byte alignment pad. Used for
// both varying and conformant+varying strings — the conformant max_count is
// hoisted to the enclosing struct by scanConformantArrays and is not written
// inline here.
func (enc *Encoder) writeVaryingString(s string) error {
	unc := enc.ToUnicode(s)
	actualLen := uint32(len(unc) / 2)
	if err := enc.writeUint32(uint32(0)); err != nil { // offset
		return fmt.Errorf("could not write string offset: %v", err)
	}
	if err := enc.writeUint32(actualLen); err != nil { // actual count
		return fmt.Errorf("could not write string actual count: %v", err)
	}
	if err := binary.Write(enc.w, enc.ch.Endianness, unc); err != nil {
		return fmt.Errorf("could not write string data: %v", err)
	}
	enc.ensureAlignment(SizeUint32)
	return nil
}
