package ndr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/jfjallid/golog"
)

var log = golog.Get("github.com/jfjallid/ndr")

// Decoder unmarshals NDR byte stream data into a Go struct representation
type Encoder struct {
	w              *bytes.Buffer // of the data
	ch             CommonHeader  // NDR common header
	ph             PrivateHeader // NDR private header
	conformantMax  []uint32      // conformant max values that were moved to the beginning of the structure
	s              interface{}   // source of data to encode
	current        []string      // keeps track of the current field being populated
	nextReferentID uint32
	includeHeaders bool
}

// NewDecoder creates a new instance of a NDR Decoder.
func NewEncoder(w *bytes.Buffer, includeHeaders bool) *Encoder {
	enc := new(Encoder)
	enc.w = w
	enc.nextReferentID = 0x00020000
	enc.ch.Endianness = binary.LittleEndian
	enc.includeHeaders = includeHeaders
	return enc
}

func (enc *Encoder) GetBytes() []byte {
	return enc.w.Bytes()
}

// Encode marshals the provided structure into NDR encoded bytes.
func (enc *Encoder) Encode(s interface{}) (buf []byte, err error) {
	enc.s = s
	enc.nextReferentID = 0x00020000
	enc.conformantMax = nil
	enc.current = nil
	if enc.includeHeaders {
		//First write an NDR ptr
		err = binary.Write(enc.w, enc.ch.Endianness, uint32(0xFFFFFFFF))
		if err != nil {
			return
		}
	}

	// Then serialize the constructed type
	err = enc.process(s, reflect.StructTag(""))
	if err != nil {
		return
	}
	// Finally, optionally prepend the common and private headers
	if enc.includeHeaders {
		header := bytes.NewBuffer([]byte{})
		err = enc.writeCommonHeader(header)
		if err != nil {
			return
		}
		err = enc.writePrivateHeader(header)
		if err != nil {
			return
		}
		return append(header.Bytes(), enc.w.Bytes()...), nil
	}

	return enc.w.Bytes(), nil
}

func (enc *Encoder) SetEndianness(order binary.ByteOrder) {
	enc.ch.Endianness = order
}

func (enc *Encoder) process(s interface{}, tag reflect.StructTag) (err error) {
	// Scan for conformant fields as their max counts are moved to the beginning
	// http://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagfcjh_37
	err = enc.scanConformantArrays(s, tag)
	if err != nil {
		return err
	}
	// Recursively fill the struct fields
	var localDef []deferedPtr
	err = enc.fill(s, tag, &localDef)
	if err != nil {
		return Errorf("could not encode: %v", err)
	}
	// Write any deferred referents associated with pointers
	for _, p := range localDef {
		err = enc.process(p.v, p.tag)
		if err != nil {
			return fmt.Errorf("could not encode deferred referent: %v", err)
		}
	}
	return nil
}

// scanConformantArrays scans the structure for embedded conformant fields and captures the maximum element counts for
// dimensions of the array that are moved to the beginning of the structure.
func (enc *Encoder) scanConformantArrays(s interface{}, tag reflect.StructTag) error {
	err := enc.conformantScan(s, tag)
	if err != nil {
		return fmt.Errorf("failed to scan for embedded conformant arrays: %v", err)
	}
	for i := range enc.conformantMax {
		//fmt.Printf("Writing conformant max value of: %d for field: %v\n", enc.conformantMax[i], enc.current)
		log.Debugf("Writing conformant max value of: %d for field: %v\n", enc.conformantMax[i], enc.current)
		enc.ensureAlignment(SizeUint32)
		err = binary.Write(enc.w, enc.ch.Endianness, enc.conformantMax[i])
		if err != nil {
			return fmt.Errorf("could not write preceding conformant max count index %d: %v", i, err)
		}
	}
	// Clear list as we may encounter new conformantMax values in defered structs
	enc.conformantMax = nil
	return nil
}

// conformantScan inspects the structure's fields for whether they are conformant.
func (enc *Encoder) conformantScan(s interface{}, tag reflect.StructTag) error {
	ndrTag := parseTags(tag)
	if ndrTag.HasValue(TagPointer) {
		return nil
	} else if ndrTag.HasValue(TagTopLevel) {
		return nil
	} else if ndrTag.HasValue(TagFullPointer) {
		return nil
	}
	v := getReflectValue(s)
	if !v.IsValid() {
		return nil
	}
	fieldName := v.Type().Name()
	//fmt.Printf("Scanning field: %s\n", fieldName)
	//fmt.Printf("Checking conformant tag for type: %v\n", v.Kind())
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			fieldTag := v.Type().Field(i).Tag
			fieldNdrTag := parseTags(fieldTag)
			// Resolve maxcount sibling field reference at struct level
			// where parent context is available.
			if mcField, ok := fieldNdrTag.Map[TagMaxCount]; ok {
				if _, parseErr := strconv.Atoi(mcField); parseErr != nil {
					var mc uint32
					var resolveErr error
					if v.Field(i).Kind() == reflect.String {
						mc, resolveErr = resolveSiblingUint16AsCodeUnits(v, mcField)
					} else {
						mc, resolveErr = resolveSiblingFieldAsUint32(v, mcField)
					}
					if resolveErr != nil {
						return resolveErr
					}
					fieldNdrTag.Map[TagMaxCount] = strconv.Itoa(int(mc))
					fieldTag = fieldNdrTag.StructTag()
				}
			}
			err := enc.conformantScan(v.Field(i), fieldTag)
			if err != nil {
				return err
			}
		}
	case reflect.String:
		if !ndrTag.HasValue(TagConformant) {
			break
		}
		var maxCount uint32
		if mcStr, ok := ndrTag.Map[TagMaxCount]; ok {
			mc, err := strconv.Atoi(mcStr)
			if err != nil {
				return fmt.Errorf("invalid maxcount tag value %q: %v", mcStr, err)
			}
			maxCount = uint32(mc)
		} else {
			// Default: compute from string content.
			// Add +1 for null terminator only when skipnull is NOT set
			// (skipnull strings have MaxCount == ActualCount).
			maxCount = uint32(len(utf16.Encode([]rune(v.String()))))
			if !ndrTag.HasValue(TagSkipNull) && !strings.HasSuffix(v.String(), "\x00") {
				maxCount++
			}
		}
		enc.conformantMax = append(enc.conformantMax, maxCount)
	case reflect.Slice:
		if !ndrTag.HasValue(TagConformant) {
			break
		}
		d, t := sliceDimensions(v.Type())
		if d > 1 {
			// For multi-dimensional arrays, get each dimension's actual length
			l, _ := parseDimensions(v)
			for i := 0; i < d; i++ {
				var dimMax uint32
				if i == 0 {
					if mcStr, ok := ndrTag.Map[TagMaxCount]; ok {
						mc, err := strconv.Atoi(mcStr)
						if err != nil {
							return fmt.Errorf("invalid maxcount tag value %q: %v", mcStr, err)
						}
						dimMax = uint32(mc)
					} else if i < len(l) {
						dimMax = uint32(l[i])
					}
				} else if i < len(l) {
					dimMax = uint32(l[i])
				}
				log.Debugf("slice field: %s, dimension: %d has a conformantMax of: %d\n", fieldName, i, dimMax)
				enc.conformantMax = append(enc.conformantMax, dimMax)
			}
		} else {
			var maxCount uint32
			if mcStr, ok := ndrTag.Map[TagMaxCount]; ok {
				mc, err := strconv.Atoi(mcStr)
				if err != nil {
					return fmt.Errorf("invalid maxcount tag value %q: %v", mcStr, err)
				}
				maxCount = uint32(mc)
			} else {
				maxCount = uint32(v.Len())
			}
			log.Debugf("slice field: %s, dimension: 0 has a conformantMax of: %d\n", fieldName, maxCount)
			enc.conformantMax = append(enc.conformantMax, maxCount)
		}
		// For string arrays there is a common max that applies to every string
		// in the array. Spec requires max_count >= actual_count; use the longest
		// string's UTF-16 code-unit length (+1 for null unless skipnull is set).
		if t.Kind() == reflect.String {
			commonMax := stringArrayCommonMax(v, ndrTag.HasValue(TagSkipNull))
			log.Debugf("string array field: %s has a conformantMax of: %d\n", fieldName, commonMax)
			enc.conformantMax = append(enc.conformantMax, commonMax)
		}
	}
	return nil
}

func (enc *Encoder) isPointer(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) (bool, error) {
	// Embedded pointer semantics (mirroring the top-level convention):
	//   `pointer` alone            → IDL [ref]: referent_id inline, null NOT allowed
	//   `pointer,fullpointer` or
	//   `fullpointer` alone        → IDL [unique]/[ptr]: referent_id inline, null allowed (writes 0)
	// `notnullptr` forces non-null for either class (pre-allocated [in,out]
	// buffers whose underlying value is zero but whose pointer must be sent).
	ndrTag := parseTags(tag)
	notNullPtr := ndrTag.HasValue(TagNotNullPtr)
	nullable := ndrTag.HasValue(TagFullPointer)
	var err error
	if ndrTag.HasValue(TagPointer) || ndrTag.HasValue(TagFullPointer) {
		ndrTag.delete(TagPointer)
		ndrTag.delete(TagFullPointer)
		if v.Kind() == reflect.Pointer && !v.IsNil() {
			err = enc.writePointer()
			if err != nil {
				return true, fmt.Errorf("could not write pointer: %v", err)
			}
			*def = append(*def, deferedPtr{v: v, tag: ndrTag.StructTag()})
		} else if v.Kind() == reflect.Invalid {
			// Nil Go pointer.
			if !nullable && !notNullPtr {
				return true, fmt.Errorf("embedded reference pointer cannot be NULL")
			}
			enc.ensureAlignment(SizePtr)
			if err = binary.Write(enc.w, enc.ch.Endianness, uint32(0)); err != nil {
				return true, fmt.Errorf("could not write null pointer: %v", err)
			}
		} else {
			zero := reflect.Zero(v.Type())
			isZero := reflect.DeepEqual(v.Interface(), zero.Interface())
			if !isZero || notNullPtr {
				err = enc.writePointer()
				if err != nil {
					return true, fmt.Errorf("could not write pointer: %v", err)
				}
				*def = append(*def, deferedPtr{v: v, tag: ndrTag.StructTag()})
			} else if nullable {
				enc.ensureAlignment(SizePtr)
				if err = binary.Write(enc.w, enc.ch.Endianness, uint32(0)); err != nil {
					return true, fmt.Errorf("could not write empty pointer: %v", err)
				}
			} else {
				return true, fmt.Errorf("embedded reference pointer cannot be NULL")
			}
		}
		return true, nil
	}
	return false, nil
}

func (enc *Encoder) isTopLevelPointer(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) (topPointer, skipReferent bool, err error) {
	var fullPointer bool
	ndrTag := parseTags(tag)
	if ndrTag.HasValue(TagTopLevel) {
		topPointer = true
		if ndrTag.HasValue(TagFullPointer) {
			fullPointer = true
		}
		// If not full pointer, write only referent and no pointer. Also cannot be null
		if v.Kind() == reflect.Invalid {
			if !fullPointer {
				err = fmt.Errorf("A referent pointer cannot be NULL!")
				return
			}
			err = binary.Write(enc.w, enc.ch.Endianness, uint32(0))
			if err != nil {
				err = fmt.Errorf("could not write pointer: %v", err)
				return
			}
			// Signal that we move on and do not write the referrent (because it is null)
			skipReferent = true
			return
		} else {
			// Nullness tracks the Go pointer, not the pointed-to value: a non-nil
			// *T that happens to point at a zero-valued struct is a valid, non-null
			// top-level pointer and its referent must still be written.
			if fullPointer {
				err = enc.writePointer()
				if err != nil {
					err = fmt.Errorf("could not write pointer: %v", err)
					return
				}
			}
			return
		}
	}

	return false, false, nil
}

// fill populates fields with values from the NDR byte stream.
func (enc *Encoder) fill(s interface{}, tag reflect.StructTag, localDef *[]deferedPtr) (err error) {
	// Before getReflectValue dereferences Go pointers, remember whether the
	// original value was a non-nil Go pointer. This is needed because
	// getReflectValue calls Elem() on pointer values, losing the nil vs
	// zero-value distinction. Without this, isPointer's DeepEqual check
	// treats a non-nil *Struct pointing to a zero-valued struct as a null
	// pointer, which is incorrect.
	goPointerNonNil := false
	if rv, ok := s.(reflect.Value); ok && rv.Kind() == reflect.Pointer && !rv.IsNil() {
		ndrTag := parseTags(tag)
		if ndrTag.HasValue(TagPointer) || ndrTag.HasValue(TagFullPointer) {
			goPointerNonNil = true
		}
	}

	v := getReflectValue(s)

	topPointer, skipReferent, err := enc.isTopLevelPointer(v, tag, localDef)
	if err != nil {
		return fmt.Errorf("could not process struct field(%s): %v", strings.Join(enc.current, "/"), err)
	}
	if skipReferent {
		return nil
	}
	if topPointer {
		ndrTags := parseTags(tag)
		ndrTags.delete(TagTopLevel)
		ndrTags.delete(TagFullPointer)
		tag = ndrTags.StructTag()
		// Continue below to write the referent
		err = enc.process(v, ndrTags.StructTag())
		if err != nil {
			return fmt.Errorf("could not process struct field(%s): %v", strings.Join(enc.current, "/"), err)
		}
		return nil
	}

	// Pointer so defer filling the referent.
	// If the original Go value was a non-nil *Struct that getReflectValue
	// dereferenced, force a pointer write even if the struct is zero-valued.
	if goPointerNonNil {
		ndrTag := parseTags(tag)
		ndrTag.delete(TagPointer)
		ndrTag.delete(TagFullPointer)
		err = enc.writePointer()
		if err != nil {
			return fmt.Errorf("could not write pointer for field(%s): %v", strings.Join(enc.current, "/"), err)
		}
		*localDef = append(*localDef, deferedPtr{v: v, tag: ndrTag.StructTag()})
		return nil
	}
	ptr, err := enc.isPointer(v, tag, localDef)
	if err != nil {
		return fmt.Errorf("could not process struct field(%s): %v", strings.Join(enc.current, "/"), err)
	}
	if ptr {
		log.Debugf("Found a ptr so skipping for now: %v\n", enc.current)
		return nil
	}
	/*
		Top-Level pointers are handled different from embedded pointers in that the data is written directly after the pointer
		instead of being deferred to later.
		Only argumens to the RPC call are considered Top-Level pointers, or the top level struct members in case of DCERPC
		If Top-Level ptr is pointing to nothing, write just 4 null bytes
		Otherwise, write a 4 byte ptr and then the actual data
		Have some trouble with LsarGetUserName encoding and decoding...
		Seems like all the "arguments" e.g., the members of the request struct for each method are top-level pointers.
		Depending on attributes in the IDL they are either full pointers or ref pointers.
		A full pointer is marshalled with a ptr and the data directly after. But if the data is a structure containing embedded pointers,
		the referent data is deferred until later.
		If it is a ref pointer, the data the pointer points to is marhalled directly inline without any pointers marshalled first.
		If a paramter has the unique keyword in IDL, that means that the pointer can be null and is considered a full pointer.
	*/

	// Populate the value from the byte stream
	switch v.Kind() {
	case reflect.Invalid:
		// NIL ptr
		err = binary.Write(enc.w, enc.ch.Endianness, uint32(0))
		if err != nil {
			return fmt.Errorf("could not fill struct field(%s): %v", strings.Join(enc.current, "/"), err)
		}
	case reflect.Struct:
		// NDR spec: struct alignment is the largest alignment of all its fields.
		// Apply padding so the struct starts at a correctly-aligned offset.
		if align := structAlignment(v.Type()); align > 1 {
			enc.ensureAlignment(align)
		}
		enc.current = append(enc.current, v.Type().Name()) //Track the current field being filled
		// in case struct is a union, track this and the selected union field for efficiency
		var unionTag reflect.Value
		var unionField string // field to fill if struct is a union
		// Deferred pointer referents are appended to localDef (owned by the
		// caller — typically process()). This ensures that when an array of
		// structs is encoded, all element bodies (with inline refIDs) are
		// written first, and ALL referents follow the entire array — matching
		// the NDR wire format verified in Wireshark.
		// Go through each field in the struct and recursively fill
		for i := 0; i < v.NumField(); i++ {
			fieldName := v.Type().Field(i).Name
			enc.current = append(enc.current, fieldName) //Track the current field being filled
			structTag := v.Type().Field(i).Tag
			ndrTag := parseTags(structTag)

			log.Debugf("Handling field: %s\n", fieldName)

			// Union handling
			if !unionTag.IsValid() {
				// Is this field a union tag?
				unionTag = enc.isUnion(v.Field(i), structTag)
			} else {
				// What is the selected field value of the union if we don't already know
				if unionField == "" {
					unionField, err = unionSelectedField(v, unionTag)
					if err != nil {
						return fmt.Errorf("could not determine selected union value field for %s with discriminat"+
							" tag %s: %v", v.Type().Name(), unionTag, err)
					}
				}
				if ndrTag.HasValue(TagUnionField) && fieldName != unionField {
					// is a union and this field has not been selected so will skip it.
					enc.current = enc.current[:len(enc.current)-1] //This field has been skipped so remove it from the current field tracker
					continue
				}
				// Selected arm of a union: align to max of all arms' alignment
				// (C706 §14.3.9/10), not just the active arm's own alignment.
				if ndrTag.HasValue(TagUnionField) && fieldName == unionField {
					if a := maxArmAlignment(v.Type()); a > 1 {
						enc.ensureAlignment(a)
					}
				}
			}

			// Resolve maxcount sibling field reference so the resolved
			// numeric value propagates into deferred pointer tags.
			if mcField, ok := ndrTag.Map[TagMaxCount]; ok {
				if _, parseErr := strconv.Atoi(mcField); parseErr != nil {
					var mc uint32
					var resolveErr error
					if v.Field(i).Kind() == reflect.String {
						mc, resolveErr = resolveSiblingUint16AsCodeUnits(v, mcField)
					} else {
						mc, resolveErr = resolveSiblingFieldAsUint32(v, mcField)
					}
					if resolveErr != nil {
						return fmt.Errorf("could not resolve maxcount for field(%s): %v",
							strings.Join(enc.current, "/"), resolveErr)
					}
					ndrTag.Map[TagMaxCount] = strconv.Itoa(int(mc))
					structTag = ndrTag.StructTag()
				}
			}

			if v.Field(i).Type().Implements(reflect.TypeOf(new(RawBytes)).Elem()) &&
				v.Field(i).Type().Kind() == reflect.Slice && v.Field(i).Type().Elem().Kind() == reflect.Uint8 {
				// field is for rawbytes
				structTag, err = addSizeToTag(v, v.Field(i), structTag)
				if err != nil {
					return fmt.Errorf("could not get rawbytes field(%s) size: %v", strings.Join(enc.current, "/"), err)
				}
				ptr, err := enc.isPointer(v.Field(i), structTag, localDef)
				if err != nil {
					return fmt.Errorf("could not process struct field(%s): %v", strings.Join(enc.current, "/"), err)
				}
				if !ptr {
					err := enc.writeRawBytes(v.Field(i), structTag)
					if err != nil {
						return fmt.Errorf("could not write raw bytes struct field(%s): %v", strings.Join(enc.current, "/"), err)
					}
				}
			} else {
				err := enc.fill(v.Field(i), structTag, localDef)
				if err != nil {
					return fmt.Errorf("could not fill struct field(%s): %v", strings.Join(enc.current, "/"), err)
				}
			}
			enc.current = enc.current[:len(enc.current)-1] //This field has been filled so remove it from the current field tracker
		}
		enc.current = enc.current[:len(enc.current)-1] //This field has been filled so remove it from the current field tracker
	case reflect.Bool:
		err := enc.writeBool(v.Bool())
		if err != nil {
			return fmt.Errorf("could not fill %s: %v", v.Type().Name(), err)
		}
	case reflect.Uint8:
		err := enc.writeUint8(uint8(v.Uint()))
		if err != nil {
			return fmt.Errorf("could not fill %s: %v", v.Type().Name(), err)
		}
	case reflect.Uint16:
		err := enc.writeUint16(uint16(v.Uint()))
		if err != nil {
			return fmt.Errorf("could not fill %s: %v", v.Type().Name(), err)
		}
	case reflect.Uint32:
		err := enc.writeUint32(uint32(v.Uint()))
		if err != nil {
			return fmt.Errorf("could not fill %s: %v", v.Type().Name(), err)
		}
	case reflect.Uint64:
		err := enc.writeUint64(v.Uint())
		if err != nil {
			return fmt.Errorf("could not fill %s: %v", v.Type().Name(), err)
		}
	case reflect.Int8:
		err := enc.writeInt8(int8(v.Int()))
		if err != nil {
			return fmt.Errorf("could not fill %s: %v", v.Type().Name(), err)
		}
	case reflect.Int16:
		err := enc.writeInt16(int16(v.Int()))
		if err != nil {
			return fmt.Errorf("could not fill %s: %v", v.Type().Name(), err)
		}
	case reflect.Int32:
		err := enc.writeInt32(int32(v.Int()))
		if err != nil {
			return fmt.Errorf("could not fill %s: %v", v.Type().Name(), err)
		}
	case reflect.Int64:
		err := enc.writeInt64(int64(v.Int()))
		if err != nil {
			return fmt.Errorf("could not fill %s: %v", v.Type().Name(), err)
		}
	case reflect.String:
		ndrTag := parseTags(tag)
		skipNull := ndrTag.HasValue(TagSkipNull)
		// Strings are always varying on the wire; the conformant max_count, when
		// applicable, is hoisted by scanConformantArrays. Per NDR strings are
		// null-terminated unless the caller opted out via `skipnull`.
		s := v.String()
		if !strings.HasSuffix(s, "\x00") && !skipNull {
			s += "\x00"
		}
		if err := enc.writeVaryingString(s); err != nil {
			return fmt.Errorf("could not write varying string: %v", err)
		}
	case reflect.Float32:
		err := enc.writeFloat32(float32(v.Float()))
		if err != nil {
			return fmt.Errorf("could not fill %v: %v", v.Type().Name(), err)
		}
	case reflect.Float64:
		err := enc.writeFloat64(v.Float())
		if err != nil {
			return fmt.Errorf("could not fill %v: %v", v.Type().Name(), err)
		}
	case reflect.Array:
		err := enc.writeFixedArray(v, tag, localDef)
		if err != nil {
			return err
		}
	case reflect.Slice:
		ndrTag := parseTags(tag)
		conformant := ndrTag.HasValue(TagConformant)
		varying := ndrTag.HasValue(TagVarying)
		if ndrTag.HasValue(TagPipe) {
			err := enc.writePipe(v, tag)
			if err != nil {
				return err
			}
			break
		}
		_, t := sliceDimensions(v.Type())
		if t.Kind() == reflect.String && !ndrTag.HasValue(subStringArrayValue) {
			// String array
			err := enc.writeStringsArray(v, tag, localDef)
			if err != nil {
				return err
			}
			break
		}
		// varying is assumed as fixed arrays use the Go array type rather than slice
		if conformant && varying {
			err := enc.writeConformantVaryingArray(v, tag, localDef)
			if err != nil {
				return err
			}
		} else if !conformant && varying {
			err := enc.writeVaryingArray(v, tag, localDef)
			if err != nil {
				return err
			}
		} else {
			//default to conformant and not varying
			err := enc.writeConformantArray(v, tag, localDef)
			if err != nil {
				return err
			}
		}
	default:
		fmt.Printf("unsupported type: %v\n", v.Kind())
		return fmt.Errorf("unsupported type")
	}
	return nil
}

func (enc *Encoder) ensureAlignment(n int) {
	diff := enc.w.Len() % n
	if diff > 0 {
		//fmt.Printf("\nUsing %d bytes alignment\n\n", n-diff)
		log.Debugf("\nUsing %d bytes alignment\n\n", n-diff)
		enc.w.Write(make([]byte, n-diff))
	}
}

// resolveSiblingUint16AsCodeUnits reads a uint16 sibling field from the parent
// struct and divides by 2 to convert from byte count to UTF-16 code unit count.
// If the sibling field is a pointer, it is dereferenced (and must be non-nil).
func resolveSiblingUint16AsCodeUnits(parent reflect.Value, fieldName string) (uint32, error) {
	field := parent.FieldByName(fieldName)
	if !field.IsValid() {
		return 0, fmt.Errorf("sibling field %q not found in struct %s", fieldName, parent.Type().Name())
	}
	if field.Kind() == reflect.Ptr {
		if field.IsNil() {
			return 0, fmt.Errorf("sibling field %q is a nil pointer", fieldName)
		}
		field = field.Elem()
	}
	if field.Kind() != reflect.Uint16 {
		return 0, fmt.Errorf("sibling field %q is %v, expected uint16", fieldName, field.Kind())
	}
	return uint32(field.Uint()) / 2, nil
}

// resolveSiblingFieldAsUint32 reads a sibling field from the parent struct and
// returns its raw integer value as uint32. Unlike resolveSiblingUint16AsCodeUnits,
// no arithmetic transformation is applied. Supports uint8/uint16/uint32/int types,
// plus pointers to those types (which are dereferenced; must be non-nil).
func resolveSiblingFieldAsUint32(parent reflect.Value, fieldName string) (uint32, error) {
	field := parent.FieldByName(fieldName)
	if !field.IsValid() {
		return 0, fmt.Errorf("sibling field %q not found in struct %s", fieldName, parent.Type().Name())
	}
	if field.Kind() == reflect.Ptr {
		if field.IsNil() {
			return 0, fmt.Errorf("sibling field %q is a nil pointer", fieldName)
		}
		field = field.Elem()
	}
	switch field.Kind() {
	case reflect.Uint8, reflect.Uint16, reflect.Uint32:
		return uint32(field.Uint()), nil
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int:
		v := field.Int()
		if v < 0 {
			return 0, fmt.Errorf("sibling field %q has negative value %d", fieldName, v)
		}
		return uint32(v), nil
	default:
		return 0, fmt.Errorf("sibling field %q is %v, expected an integer type", fieldName, field.Kind())
	}
}

func (enc *Encoder) writeBool(val bool) error {
	return binary.Write(enc.w, enc.ch.Endianness, val)
}

func (enc *Encoder) writeUint8(val uint8) error {
	//enc.ensureAlignment(SizeUint8)
	return binary.Write(enc.w, enc.ch.Endianness, val)
}

func (enc *Encoder) writeUint16(val uint16) error {
	enc.ensureAlignment(SizeUint16)
	return binary.Write(enc.w, enc.ch.Endianness, val)
}

// readUint32 reads bytes representing a 32bit unsigned integer.
func (enc *Encoder) writeUint32(val uint32) error {
	enc.ensureAlignment(SizeUint32)
	return binary.Write(enc.w, enc.ch.Endianness, val)
}

func (enc *Encoder) writeUint64(val uint64) error {
	enc.ensureAlignment(SizeUint64)
	return binary.Write(enc.w, enc.ch.Endianness, val)
}

func (enc *Encoder) writeInt8(val int8) error {
	//enc.ensureAlignment(SizeUint8)
	return binary.Write(enc.w, enc.ch.Endianness, val)
}

func (enc *Encoder) writeInt16(val int16) error {
	enc.ensureAlignment(SizeUint16)
	return binary.Write(enc.w, enc.ch.Endianness, val)
}

func (enc *Encoder) writeInt32(val int32) error {
	enc.ensureAlignment(SizeUint32)
	return binary.Write(enc.w, enc.ch.Endianness, val)
}

func (enc *Encoder) writeInt64(val int64) error {
	enc.ensureAlignment(SizeUint64)
	return binary.Write(enc.w, enc.ch.Endianness, val)
}

func (enc *Encoder) writeFloat32(val float32) (err error) {
	enc.ensureAlignment(SizeSingle)
	return binary.Write(enc.w, enc.ch.Endianness, val)
}

func (enc *Encoder) writeFloat64(val float64) (err error) {
	enc.ensureAlignment(SizeDouble)
	return binary.Write(enc.w, enc.ch.Endianness, val)
}

func (enc *Encoder) writePointer() error {
	enc.ensureAlignment(SizePtr)
	refId := enc.nextReferentID
	enc.nextReferentID += 4
	//fmt.Printf("Writing pointer with refId: 0x%08x\n", refId)
	log.Debugf("Writing pointer with refId: 0x%08x\n", refId)
	return binary.Write(enc.w, enc.ch.Endianness, refId)
}
