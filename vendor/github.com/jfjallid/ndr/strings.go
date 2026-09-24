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
	conformant := ndrTag.HasValue(TagConformant)
	varying := ndrTag.HasValue(TagVarying)
	elemTag := reflect.StructTag(subStringArrayTag)

	// A conformant-only array carries no offset/actual count of its own: the
	// hoisted max count is the element count. Only a varying array has that
	// metadata inline. The elements are varying strings either way.
	if conformant && !varying {
		if err := dec.fillConformantArray(v, elemTag, def); err != nil {
			return fmt.Errorf("could not read conformant string array: %w", err)
		}
		// The common max that applies to every string in the array is queued
		// after the array's own dimensions, so it is claimed last.
		if _, err := dec.precedingMax(); err != nil {
			return err
		}
		return nil
	}

	if conformant {
		// The per-dimension maxima and the common per-string maximum are
		// consumed here; the varying metadata read below sizes the array.
		for i := 0; i < d; i++ {
			if _, err := dec.precedingMax(); err != nil {
				return err
			}
		}
		if _, err := dec.precedingMax(); err != nil {
			return err
		}
	}
	if err := dec.fillVaryingArray(v, elemTag, def); err != nil {
		return fmt.Errorf("could not read string array: %w", err)
	}
	return nil
}

func (enc *Encoder) writeStringsArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	// Conformant max values (array dimensions + common string max) are already
	// written by process()/conformantScan(). What remains is the array body,
	// with each element encoded as a varying string.
	ndrTag := parseTags(tag)
	elemTag := reflect.StructTag(subStringArrayTag)

	// Only a varying array carries an inline offset/actual count. Emitting one
	// for a conformant-only array described it on the wire as conformant+varying.
	if ndrTag.HasValue(TagConformant) && !ndrTag.HasValue(TagVarying) {
		if err := enc.writeConformantArray(v, elemTag, def); err != nil {
			return fmt.Errorf("could not write conformant string array: %w", err)
		}
		return nil
	}
	if err := enc.writeVaryingArray(v, elemTag, def); err != nil {
		return fmt.Errorf("could not write string array: %w", err)
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
// offset (0) + actual_count + UTF-16LE data. Used for
// both varying and conformant+varying strings — the conformant max_count is
// hoisted to the enclosing struct by scanConformantArrays and is not written
// inline here.
func (enc *Encoder) writeVaryingString(s string) error {
	unc := enc.ToUnicode(s)
	actualLen := uint32(len(unc) / 2)
	if err := enc.writeUint32(uint32(0)); err != nil { // offset
		return fmt.Errorf("could not write string offset: %w", err)
	}
	if err := enc.writeUint32(actualLen); err != nil { // actual count
		return fmt.Errorf("could not write string actual count: %w", err)
	}
	if err := binary.Write(enc.w, enc.ch.Endianness, unc); err != nil {
		return fmt.Errorf("could not write string data: %w", err)
	}
	// No trailing padding: C706 aligns each primitive as it is written, so any
	// gap belongs to whatever comes next. Emitting it here both diverged from
	// the wire format and desynchronised the decoder, which never consumed it,
	// for any string followed by a field of alignment less than 4.
	return nil
}
