package ndr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	//"io"
	"reflect"
	"strings"
)

// Decoder unmarshals NDR byte stream data into a Go struct representation
type Encoder struct {
	w             	*bytes.Buffer // of the data
	ch            	CommonHeader  // NDR common header
	ph            	PrivateHeader // NDR private header
	conformantMax 	[]uint32      // conformant max values that were moved to the beginning of the structure
	s             	interface{}   // source of data to encode
	current       	[]string      // keeps track of the current field being populated
	nextReferentID	uint32
	includeHeaders	bool
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
	//First write an NDR ptr
	err = binary.Write(enc.w, binary.LittleEndian, uint32(0xFFFFFFFF))
	if err != nil {
		return
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
		err = binary.Write(enc.w, binary.LittleEndian, enc.conformantMax[i])
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
	}
	v := getReflectValue(s)
	//fieldName := v.Type().Name()
	//fmt.Printf("Scanning field: %s\n", fieldName)
	//fmt.Printf("Checking conformant tag for type: %v\n", v.Kind())
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			err := enc.conformantScan(v.Field(i), v.Type().Field(i).Tag)
			if err != nil {
				return err
			}
		}
	case reflect.String:
		if !ndrTag.HasValue(TagConformant) {
			break
		}
		//NOTE Conformant Max should be max num of elements (uint16) not max num of bytes
		enc.conformantMax = append(enc.conformantMax, uint32(v.Len()))
	case reflect.Slice:
		if !ndrTag.HasValue(TagConformant) {
			break
		}
		d, t := sliceDimensions(v.Type())
		for i := 0; i < d; i++ {
			//fmt.Printf("slice field: %s, dimension: %d has a conformantMax of: %d\n", fieldName, i, v.Len())
			enc.conformantMax = append(enc.conformantMax, uint32(v.Len()))
		}
		// For string arrays there is a common max for the strings within the array.
		if t.Kind() == reflect.String {
			//TODO
			//fmt.Printf("string array field: %s has a conformantMax of: uint32(0)\n", fieldName)
			enc.conformantMax = append(enc.conformantMax, uint32(0))
		}
	}
	return nil
}

func (enc *Encoder) isPointer(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) (bool, error) {
	// Pointer so defer filling the referent
	ndrTag := parseTags(tag)
	var err error
	if ndrTag.HasValue(TagPointer) {
		ndrTag.delete(TagPointer)
		if v.Kind() == reflect.Pointer && !v.IsNil() {
			err = enc.writePointer()
			if err != nil {
				return true, fmt.Errorf("could not write pointer: %v", err)
			}
			// if pointer is not zero add to the deferred items at end of stream
			*def = append(*def, deferedPtr{v: v, tag: ndrTag.StructTag()})
		} else {
			zero := reflect.Zero(v.Type())
			if !reflect.DeepEqual(v.Interface(), zero.Interface()) {
				//fmt.Println("Found non-zero structure with pointer tag")
				err = enc.writePointer()
				if err != nil {
					return true, fmt.Errorf("could not write pointer: %v", err)
				}
				// if pointer is not zero add to the deferred items at end of stream
				*def = append(*def, deferedPtr{v: v, tag: ndrTag.StructTag()})
			} else {
				if v.Kind() == reflect.String {
					//fmt.Println("Writing pointer for empty string")	
					err = enc.writePointer()
					if err != nil {
						return true, fmt.Errorf("could not write pointer: %v", err)
					}
					// if pointer is not zero add to the deferred items at end of stream
					*def = append(*def, deferedPtr{v: v, tag: ndrTag.StructTag()})
				} else {
					err = binary.Write(enc.w, binary.LittleEndian, uint32(0))
					if err != nil {
						return true, fmt.Errorf("could not write empty pointer: %v", err)
					}
				}
			}
		}
		return true, nil
	}
	return false, nil
}

// fill populates fields with values from the NDR byte stream.
func (enc *Encoder) fill(s interface{}, tag reflect.StructTag, localDef *[]deferedPtr) (err error) {
	v := getReflectValue(s)

	// Pointer so defer filling the referent
	ptr, err := enc.isPointer(v, tag, localDef)
	if err != nil {
		return fmt.Errorf("could not process struct field(%s): %v", strings.Join(enc.current, "/"), err)
	}
	if ptr {
		//fmt.Printf("Found a ptr so skipping for now: %v\n", enc.current)
		return nil
	}

	// Populate the value from the byte stream
	switch v.Kind() {
	case reflect.Struct:
		enc.current = append(enc.current, v.Type().Name()) //Track the current field being filled
		// in case struct is a union, track this and the selected union field for efficiency
		var unionTag reflect.Value
		var unionField string // field to fill if struct is a union
		// Go through each field in the struct and recursively fill
		for i := 0; i < v.NumField(); i++ {
			fieldName := v.Type().Field(i).Name
			enc.current = append(enc.current, fieldName) //Track the current field being filled
			//fmt.Fprintf(os.Stderr, "DEBUG encoding: %s\n", strings.Join(enc.current, "/"))
			structTag := v.Type().Field(i).Tag
			ndrTag := parseTags(structTag)

			//fmt.Printf("Handling field: %s\n", fieldName)

			// Union handling
			if !unionTag.IsValid() {
				// Is this field a union tag?
				//unionTag = enc.isUnion(v.Field(i), structTag)
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
			}

			err := enc.fill(v.Field(i), structTag, localDef)
			if err != nil {
				return fmt.Errorf("could not fill struct field(%s): %v", strings.Join(enc.current, "/"), err)
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
		conformant := ndrTag.HasValue(TagConformant)
		// strings are always varying so this is assumed without an explicit tag
		var err error
		if conformant {
			err = enc.writeConformantVaryingString(v.String())
			if err != nil {
				return fmt.Errorf("could not write with conformant varying string: %v", err)
			}
		} else {
			//s, err = enc.readVaryingString(localDef)
			//if err != nil {
			//	return fmt.Errorf("could not fill with varying string: %v", err)
			//}
			return fmt.Errorf("Haven't implemented varying strings yet")
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
		//if v.Type().Implements(reflect.TypeOf(new(RawBytes)).Elem()) && v.Type().Elem().Kind() == reflect.Uint8 {
		//	//field is for rawbytes
		//	err := enc.readRawBytes(v, tag)
		//	if err != nil {
		//		return fmt.Errorf("could not fill raw bytes struct field(%s): %v", strings.Join(enc.current, "/"), err)
		//	}
		//	break
		//}
		ndrTag := parseTags(tag)
		conformant := ndrTag.HasValue(TagConformant)
		varying := ndrTag.HasValue(TagVarying)
		//if ndrTag.HasValue(TagPipe) {
		//	err := enc.fillPipe(v, tag)
		//	if err != nil {
		//		return err
		//	}
		//	break
		//}
		//_, t := sliceDimensions(v.Type())
		//if t.Kind() == reflect.String && !ndrTag.HasValue(subStringArrayValue) {
		//	// String array
		//	err := enc.readStringsArray(v, tag, localDef)
		//	if err != nil {
		//		return err
		//	}
		//	break
		//}
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
		return fmt.Errorf("unsupported type")
	}
	return nil
}

func (enc *Encoder) ensureAlignment(n int) {
    diff := enc.w.Len() % n
    if diff > 0 {
		//fmt.Printf("\nUsing %d bytes alignment\n\n", n-diff)
        enc.w.Write(make([]byte, n - diff))
    }
}

func (enc *Encoder) writeBool(val bool) (error) {
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

func (enc *Encoder) writeInt8(val int8) (error) {
	//enc.ensureAlignment(SizeUint8)
	return binary.Write(enc.w, enc.ch.Endianness, val)
}

func (enc *Encoder) writeInt16(val int16) (error) {
	enc.ensureAlignment(SizeUint16)
	return binary.Write(enc.w, enc.ch.Endianness, val)
}

func (enc *Encoder) writeInt32(val int32) (error) {
	enc.ensureAlignment(SizeUint32)
	return binary.Write(enc.w, enc.ch.Endianness, val)
}

func (enc *Encoder) writeInt64(val int64) (error) {
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
	return binary.Write(enc.w, enc.ch.Endianness, refId)
}	

