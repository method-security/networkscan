// Package ndr provides the ability to unmarshal NDR encoded byte steams into Go data structures
package ndr

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// Struct tag values
const (
	TagConformant  = "conformant"
	TagVarying     = "varying"
	TagPointer     = "pointer"
	TagTopLevel    = "toplevel"
	TagFullPointer = "fullpointer"
	TagPipe        = "pipe"
	TagSkipNull    = "skipnull"
	TagMaxCount    = "maxcount"
	// TagNotNullPtr forces an embedded pointer field to emit a non-NULL
	// referent ID even when the underlying value is the zero value of its
	// type. Useful for [in,out] string buffer parameters where the client
	// pre-allocates space (Length=0, MaximumLength=N) but must still send a
	// non-NULL Buffer pointer so the server has somewhere to write into.
	TagNotNullPtr = "notnullptr"
)

// Decoder unmarshals NDR byte stream data into a Go struct representation
type Decoder struct {
	r             *bufio.Reader // source of the data
	src           io.Reader     // original source, used to estimate the bytes remaining
	pos           int           // bytes consumed from the alignment-relevant stream (reset after any header prefix)
	ch            CommonHeader  // NDR common header
	ph            PrivateHeader // NDR private header
	conformantMax []uint32      // conformant max values that were moved to the beginning of the structure
	s             any           // pointer to the structure being populated
	current       []string      // keeps track of the current field being populated
	includeHeader bool
	maxElements   int  // upper bound on elements allocated for a single array/string/pipe
	strictTags    bool // reject unrecognised ndr struct tags
}

type deferedPtr struct {
	v   reflect.Value
	tag reflect.StructTag
	p   uint32
}

// NewDecoder creates a new instance of a NDR Decoder.
func NewDecoder(r io.Reader, includeHeader bool) *Decoder {
	dec := new(Decoder)
	dec.r = bufio.NewReader(r)
	dec.src = r
	dec.includeHeader = includeHeader
	dec.maxElements = DefaultMaxElements
	dec.strictTags = true
	return dec
}

// SetStrictTags controls whether unrecognised `ndr:"..."` struct tags are
// rejected. It is on by default: an unknown tag is almost always a typo, and
// because such tags used to be ignored the mistake showed up as a silently
// wrong wire format instead of an error. Turn it off to decode a struct whose
// tags cannot be corrected.
func (dec *Decoder) SetStrictTags(strict bool) {
	dec.strictTags = strict
}

// SetMaxElements sets the upper bound on the number of elements the decoder
// will allocate for any single array, string or pipe. Counts come straight off
// the wire, so this bounds the memory a malformed or hostile stream can make
// the decoder commit. Values below 1 are ignored. See DefaultMaxElements.
func (dec *Decoder) SetMaxElements(n int) {
	if n > 0 {
		dec.maxElements = n
	}
}

// Decode unmarshals the NDR encoded bytes into the pointer of a struct provided.
func (dec *Decoder) Decode(s interface{}) (err error) {
	// Decoding is driven by reflection over caller-supplied types against
	// caller-supplied bytes. A mismatch between the two should surface as an
	// error rather than taking down the calling program, so contain any panic
	// raised below and report the field path it happened on.
	defer func() {
		if r := recover(); r != nil {
			err = Errorf("panic while decoding field(%s): %v", strings.Join(dec.current, "/"), r)
		}
	}()
	dec.s = s
	if dec.strictTags {
		if err = checkTags(s); err != nil {
			return err
		}
	}
	if dec.includeHeader {
		if err = dec.readCommonHeader(); err != nil {
			return err
		}
		if err = dec.readPrivateHeader(); err != nil {
			return err
		}
	}
	if dec.ch.Endianness == nil {
		dec.ch.Endianness = binary.LittleEndian
	}
	// Alignment is measured from the start of the object buffer, not from the
	// start of the octet stream, so discard whatever the header parsing above
	// consumed. The common and private headers are both multiples of 8 octets,
	// so this only matters for keeping the counter honest.
	dec.pos = 0
	if dec.includeHeader {
		// The object buffer opens with the referent ID of the top-level unique
		// pointer. Its value is not needed, but it occupies octets 0-3 of the
		// buffer and therefore has to be counted: the encoder writes that same
		// pointer into the buffer it aligns against, so skipping it without
		// advancing the counter left the two sides 4 octets out of step and
		// silently corrupted any type containing an 8-octet-aligned field.
		if err = dec.discard(SizePtr); err != nil {
			return Errorf("unable to process byte stream: %w", err)
		}
	}

	return dec.process(s, reflect.StructTag(""))
}

func (dec *Decoder) SetEndianness(order binary.ByteOrder) {
	dec.ch.Endianness = order
}

func (dec *Decoder) process(s interface{}, tag reflect.StructTag) error {
	// Conformant max counts are hoisted to the start of the construct they
	// belong to, so they are owned by this scope alone. A nested construct — a
	// deferred referent, or a top-level parameter — hoists its own to its own
	// start and must not see, or be seen by, the enclosing list.
	//
	// The list is consumed from the front by precedingMax, so sharing one queue
	// across scopes was doubly wrong: an entry the enclosing fill left behind
	// would both cause an extra uint32 to be read off the stream here, and be
	// handed to the first conformant field of this scope in place of its own
	// max count.
	outer := dec.conformantMax
	dec.conformantMax = nil
	defer func() { dec.conformantMax = outer }()

	// Scan for conformant fields as their max counts are moved to the beginning
	// http://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagfcjh_37
	// Find all fields and values that are conformantMax and add to list
	err := dec.scanConformantArrays(s, tag)
	if err != nil {
		return err
	}
	// Recursively fill the struct fields
	var localDef []deferedPtr
	err = dec.fill(s, tag, &localDef)
	if err != nil {
		//fmt.Printf("%+v\n", s)
		return Errorf("could not decode: %w", err)
	}
	// Every max count hoisted to the start of this construct should have been
	// claimed by the field it belongs to. Anything left means the scan walked a
	// field the fill did not, so the stream position is already past data that
	// was never used.
	if n := len(dec.conformantMax); n > 0 {
		log.Debugf("%d conformant max count(s) went unclaimed for field: %v\n", n, dec.current)
	}
	// Read any deferred referents associated with pointers
	for _, p := range localDef {
		err = dec.process(p.v, p.tag)
		if err != nil {
			return fmt.Errorf("could not decode deferred referent: %w", err)
		}
	}
	return nil
}

// scanConformantArrays scans the structure for embedded conformant fields and captures the maximum element counts for
// dimensions of the array that are moved to the beginning of the structure.
func (dec *Decoder) scanConformantArrays(s interface{}, tag reflect.StructTag) error {
	err := dec.conformantScan(s, tag)
	if err != nil {
		return fmt.Errorf("failed to scan for embedded conformant arrays: %w", err)
	}
	//fmt.Printf("Found %d conformant Max values for tag: %v, field: %v\n", len(dec.conformantMax), tag, dec.current)
	for i := range dec.conformantMax {
		dec.conformantMax[i], err = dec.readUint32()
		//fmt.Printf("Conformant max: %d for field: %v\n", dec.conformantMax[i], dec.current)
		if err != nil {
			return fmt.Errorf("could not read preceding conformant max count index %d: %w", i, err)
		}
	}
	return nil
}

// conformantScan inspects the structure's fields for whether they are conformant.
func (dec *Decoder) conformantScan(s interface{}, tag reflect.StructTag) error {
	ndrTag := parseTags(tag)
	if ndrTag.HasValue(TagPointer) {
		return nil
	} else if ndrTag.HasValue(TagTopLevel) {
		return nil
	} else if ndrTag.HasValue(TagFullPointer) {
		return nil
	}
	v := getReflectValue(s)

	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).PkgPath != "" {
				continue // unexported: no NDR representation
			}
			// Union arms are alternatives, so at most one of them is present on
			// the wire. Scanning all of them hoisted a max count for every arm,
			// which both desynchronised the stream and left unclaimed entries
			// behind. An arm that genuinely needs hoisting cannot be encoded at
			// all, so say so rather than emitting bytes no peer can parse.
			if ft := parseTags(v.Type().Field(i).Tag); ft.HasValue(TagUnionField) {
				if err := checkUnionArm(v.Type().Name(), v.Type().Field(i).Name,
					v.Type().Field(i).Type, v.Type().Field(i).Tag); err != nil {
					return err
				}
				continue
			}
			// Handle edge case where uninitialized struct (nil ptr) contains a conformant array
			if v.Field(i).Kind() == reflect.Pointer && v.Field(i).IsNil() {
				// Handle when struct pointer is nil
				v.Field(i).Set(reflect.New(v.Field(i).Type().Elem()))
			}

			err := dec.conformantScan(v.Field(i), v.Type().Field(i).Tag)
			if err != nil {
				return err
			}
		}
	case reflect.String:
		if !ndrTag.HasValue(TagConformant) {
			break
		}
		dec.conformantMax = append(dec.conformantMax, uint32(0))
	case reflect.Slice:
		if !ndrTag.HasValue(TagConformant) {
			break
		}
		d, t := sliceDimensions(v.Type())
		for i := 0; i < d; i++ {
			dec.conformantMax = append(dec.conformantMax, uint32(0))
		}
		// For string arrays there is a common max for the strings within the array.
		if t.Kind() == reflect.String {
			dec.conformantMax = append(dec.conformantMax, uint32(0))
		}
	}
	return nil
}

func (dec *Decoder) isPointer(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) (bool, error) {
	// Pointer so defer filling the referent
	ndrTag := parseTags(tag)
	if ndrTag.HasValue(TagPointer) || ndrTag.HasValue(TagFullPointer) {
		p, err := dec.readUint32()
		if err != nil {
			return true, fmt.Errorf("could not read pointer: %w", err)
		}
		ndrTag.delete(TagPointer)
		ndrTag.delete(TagFullPointer)
		if p != 0 {
			// if pointer is not zero add to the deferred items at end of stream
			*def = append(*def, deferedPtr{v, ndrTag.StructTag(), p})
		}
		return true, nil
	}
	return false, nil
}

func getReflectValue(s interface{}) (v reflect.Value) {
	if r, ok := s.(reflect.Value); ok {
		if r.Kind() == reflect.Pointer {
			v = r.Elem()
		} else {
			v = r
		}
		//fmt.Printf("getReflectedValue input & output: %v\n", v.Kind())
	} else {
		if reflect.ValueOf(s).Kind() == reflect.Ptr {
			//fmt.Printf("getReflectedValue input is a ptr\n")
			v = reflect.ValueOf(s).Elem()
			//fmt.Printf("getReflectedValue output: %v\n", v.Kind())
			//} else {
			//	fmt.Printf("getReflectedValue input is of unknown value\n")
		}
	}
	return
}

// fill populates fields with values from the NDR byte stream.
func (dec *Decoder) fill(s interface{}, tag reflect.StructTag, localDef *[]deferedPtr) error {
	v := getReflectValue(s)

	//TODO Is this correct?
	ndrTag := parseTags(tag)
	if ndrTag.HasValue(TagTopLevel) {
		ndrTag.delete(TagTopLevel)
		if ndrTag.HasValue(TagFullPointer) {
			ndrTag.delete(TagFullPointer)
			//fmt.Printf("reading top-level ptr for field: %v\n", v.Type().Name())
			p, err := dec.readUint32()
			if err != nil {
				return fmt.Errorf("could not read pointer: %w", err)
			}
			if p == 0 {
				// Top-Level null pointer so nothing else to read here
				return nil
			}
			//fmt.Printf("[debug] full ptr value: 0x%08x\n", p)
		}
		// recurse down
		//fmt.Println("Calling process() on struct field")
		err := dec.process(v, ndrTag.StructTag())
		if err != nil {
			return fmt.Errorf("could not process struct field(%s): %w", strings.Join(dec.current, "/"), err)
		}
		// Done with this parameter
		return nil
	}

	// Pointer so defer filling the referent
	ptr, err := dec.isPointer(v, tag, localDef)
	if err != nil {
		return fmt.Errorf("could not process struct field(%s): %w", strings.Join(dec.current, "/"), err)
	}
	if ptr {
		return nil
	}
	/*
		A bit complex to handle pointers:
		By default, IDL top-level pointers are [ref] pointers unless there is the [unique] or [ptr] attribute, where top-level means part of the RPC function argument list.
		For top-level [ref] pointers, there is no pointer representation, only the referent.
		For top-level [unique] or [ptr] pointers (full pointers), the referent follows directly after the ptr representation.
		If the top-level pointer points to another pointer such as PRPC_UNICODE_STRING* and is a [ref] pointer,
		there will be no initial pointer representation due to [ref] but PRPC.. is a pointer in itself (double pointers) so
		the second pointer gets a 4 byte ref id ptr representation followed by the representation of the referrent (RPC_UNICODE_STRING).
		Since this contains an embedded pointer, another ref id ptr is written before the string representation.
		After the entire top-level parameter is completely marshalled we move on to the next.
		If this is a [unique] pointer (full] we first write a ptr representation, followed by the second ptr representation, followed by the referent.
	*/

	// Populate the value from the byte stream
	switch v.Kind() {
	case reflect.Struct:
		// NDR spec: struct alignment is the largest alignment of all its fields.
		// Consume padding so the struct starts at a correctly-aligned offset.
		if align := structAlignment(v.Type()); align > 1 {
			if err := dec.ensureAlignment(align); err != nil {
				return fmt.Errorf("could not align struct %s: %w", v.Type().Name(), err)
			}
		}
		dec.current = append(dec.current, v.Type().Name()) //Track the current field being filled
		// in case struct is a union, track this and the selected union field for efficiency
		var unionTag reflect.Value
		var unionField string // field to fill if struct is a union
		// Deferred pointer referents are appended to localDef (owned by the
		// caller — typically process()). This ensures that when an array of
		// structs is decoded, all element bodies (with inline refIDs) are
		// read first, and ALL referents are read after the entire array —
		// matching the NDR wire format verified in Wireshark.
		// Go through each field in the struct and recursively fill
		for i := 0; i < v.NumField(); i++ {
			// Unexported fields have no NDR representation. Skipping them
			// mirrors encoding/json and keeps reflect from panicking on a
			// value it is not allowed to read or set.
			if v.Type().Field(i).PkgPath != "" {
				continue
			}
			fieldName := v.Type().Field(i).Name
			dec.current = append(dec.current, fieldName) //Track the current field being filled
			structTag := v.Type().Field(i).Tag
			ndrTag := parseTags(structTag)
			if v.Field(i).Kind() == reflect.Pointer && v.Field(i).IsNil() {
				// Handle when struct pointer is nil
				v.Field(i).Set(reflect.New(v.Field(i).Type().Elem()))
			}

			// Union handling
			if !unionTag.IsValid() {
				// Is this field a union tag?
				unionTag, err = dec.isUnion(v.Field(i), structTag)
				if err != nil {
					return fmt.Errorf("could not process union discriminant field(%s): %w", strings.Join(dec.current, "/"), err)
				}
			} else {
				// What is the selected field value of the union if we don't already know
				if unionField == "" {
					unionField, err = unionSelectedField(v, unionTag)
					if err != nil {
						return fmt.Errorf("could not determine selected union value field for %s with discriminat"+
							" tag %s: %w", v.Type().Name(), unionTag, err)
					}
				}
				if ndrTag.HasValue(TagUnionField) && fieldName != unionField {
					// is a union and this field has not been selected so will skip it.
					dec.current = dec.current[:len(dec.current)-1] //This field has been skipped so remove it from the current field tracker
					continue
				}
				// Selected arm of a union: align to max of all arms' alignment
				// (C706 §14.3.9/10), not just the active arm's own alignment.
				if ndrTag.HasValue(TagUnionField) && fieldName == unionField {
					if a := maxArmAlignment(v.Type()); a > 1 {
						if err := dec.ensureAlignment(a); err != nil {
							return fmt.Errorf("could not align union arm %s: %w", fieldName, err)
						}
					}
				}
			}

			// Check if field is a pointer
			if v.Field(i).Type().Implements(reflect.TypeOf(new(RawBytes)).Elem()) &&
				v.Field(i).Type().Kind() == reflect.Slice && v.Field(i).Type().Elem().Kind() == reflect.Uint8 {
				//field is for rawbytes
				structTag, err = addSizeToTag(v, v.Field(i), structTag)
				if err != nil {
					return fmt.Errorf("could not get rawbytes field(%s) size: %w", strings.Join(dec.current, "/"), err)
				}
				ptr, err := dec.isPointer(v.Field(i), structTag, localDef)
				if err != nil {
					return fmt.Errorf("could not process struct field(%s): %w", strings.Join(dec.current, "/"), err)
				}
				if !ptr {
					err := dec.readRawBytes(v.Field(i), structTag)
					if err != nil {
						return fmt.Errorf("could not fill raw bytes struct field(%s): %w", strings.Join(dec.current, "/"), err)
					}
				}
			} else {
				err := dec.fill(v.Field(i), structTag, localDef)
				if err != nil {
					return fmt.Errorf("could not fill struct field(%s): %w", strings.Join(dec.current, "/"), err)
				}
			}
			dec.current = dec.current[:len(dec.current)-1] //This field has been filled so remove it from the current field tracker
		}
		dec.current = dec.current[:len(dec.current)-1] //This field has been filled so remove it from the current field tracker
	case reflect.Bool:
		i, err := dec.readBool()
		if err != nil {
			return fmt.Errorf("could not fill %s: %w", v.Type().Name(), err)
		}
		v.Set(reflect.ValueOf(i).Convert(v.Type()))
	case reflect.Uint8:
		i, err := dec.readUint8()
		if err != nil {
			return fmt.Errorf("could not fill %s: %w", v.Type().Name(), err)
		}
		v.Set(reflect.ValueOf(i).Convert(v.Type()))
	case reflect.Uint16:
		i, err := dec.readUint16()
		if err != nil {
			return fmt.Errorf("could not fill %s: %w", v.Type().Name(), err)
		}
		v.Set(reflect.ValueOf(i).Convert(v.Type()))
	case reflect.Uint32:
		i, err := dec.readUint32()
		if err != nil {
			return fmt.Errorf("could not fill %s: %w", v.Type().Name(), err)
		}
		v.Set(reflect.ValueOf(i).Convert(v.Type())) // Support handling of custom types based on uint32
	case reflect.Uint64:
		i, err := dec.readUint64()
		if err != nil {
			return fmt.Errorf("could not fill %s: %w", v.Type().Name(), err)
		}
		v.Set(reflect.ValueOf(i).Convert(v.Type()))
	case reflect.Int8:
		i, err := dec.readInt8()
		if err != nil {
			return fmt.Errorf("could not fill %s: %w", v.Type().Name(), err)
		}
		v.Set(reflect.ValueOf(i).Convert(v.Type()))
	case reflect.Int16:
		i, err := dec.readInt16()
		if err != nil {
			return fmt.Errorf("could not fill %s: %w", v.Type().Name(), err)
		}
		v.Set(reflect.ValueOf(i).Convert(v.Type()))
	case reflect.Int32:
		i, err := dec.readInt32()
		if err != nil {
			return fmt.Errorf("could not fill %s: %w", v.Type().Name(), err)
		}
		v.Set(reflect.ValueOf(i).Convert(v.Type()))
	case reflect.Int64:
		i, err := dec.readInt64()
		if err != nil {
			return fmt.Errorf("could not fill %s: %w", v.Type().Name(), err)
		}
		v.Set(reflect.ValueOf(i).Convert(v.Type()))
	case reflect.String:
		ndrTag := parseTags(tag)
		conformant := ndrTag.HasValue(TagConformant)
		// strings are always varying so this is assumed without an explicit tag
		var s string
		var err error
		if conformant {
			s, err = dec.readConformantVaryingString(localDef)
			if err != nil {
				return fmt.Errorf("could not fill with conformant varying string: %w", err)
			}
		} else {
			s, err = dec.readVaryingString(localDef)
			if err != nil {
				return fmt.Errorf("could not fill with varying string: %w", err)
			}
		}
		v.Set(reflect.ValueOf(s).Convert(v.Type()))
	case reflect.Float32:
		i, err := dec.readFloat32()
		if err != nil {
			return fmt.Errorf("could not fill %v: %w", v.Type().Name(), err)
		}
		v.Set(reflect.ValueOf(i).Convert(v.Type()))
	case reflect.Float64:
		i, err := dec.readFloat64()
		if err != nil {
			return fmt.Errorf("could not fill %v: %w", v.Type().Name(), err)
		}
		v.Set(reflect.ValueOf(i).Convert(v.Type()))
	case reflect.Array:
		err := dec.fillFixedArray(v, tag, localDef)
		if err != nil {
			return err
		}
	case reflect.Slice:
		if v.Type().Implements(reflect.TypeOf(new(RawBytes)).Elem()) && v.Type().Elem().Kind() == reflect.Uint8 {
			//field is for rawbytes
			err := dec.readRawBytes(v, tag)
			if err != nil {
				return fmt.Errorf("could not fill raw bytes struct field(%s): %w", strings.Join(dec.current, "/"), err)
			}
			break
		}
		ndrTag := parseTags(tag)
		conformant := ndrTag.HasValue(TagConformant)
		varying := ndrTag.HasValue(TagVarying)
		if ndrTag.HasValue(TagPipe) {
			err := dec.fillPipe(v, tag)
			if err != nil {
				return err
			}
			break
		}
		_, t := sliceDimensions(v.Type())
		if t.Kind() == reflect.String && !ndrTag.HasValue(subStringArrayValue) {
			// String array
			err := dec.readStringsArray(v, tag, localDef)
			if err != nil {
				return err
			}
			break
		}
		// varying is assumed as fixed arrays use the Go array type rather than slice
		if conformant && varying {
			err := dec.fillConformantVaryingArray(v, tag, localDef)
			if err != nil {
				return err
			}
		} else if !conformant && varying {
			err := dec.fillVaryingArray(v, tag, localDef)
			if err != nil {
				return err
			}
		} else {
			//default to conformant and not varying
			err := dec.fillConformantArray(v, tag, localDef)
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported type %s for field(%s)", v.Kind(), strings.Join(dec.current, "/"))
	}
	return nil
}

// readBytes returns a number of bytes from the NDR byte stream.
func (dec *Decoder) readBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(dec.r, b); err != nil {
		return b, fmt.Errorf("error reading bytes from stream: %w", err)
	}
	dec.pos += n
	return b, nil
}

// readByte reads a single byte from the stream and advances the position
// counter used for alignment. Header-parsing paths, which run before the
// alignment-relevant stream begins, call dec.r.ReadByte() directly.
func (dec *Decoder) readByte() (byte, error) {
	b, err := dec.r.ReadByte()
	if err != nil {
		return 0, err
	}
	dec.pos++
	return b, nil
}

// discard skips n bytes and advances the position counter. A short discard is
// reported as an error so that a truncated stream cannot silently desynchronise
// the alignment counter from the reader.
func (dec *Decoder) discard(n int) error {
	m, err := dec.r.Discard(n)
	dec.pos += m
	if err != nil {
		return err
	}
	if m != n {
		return io.ErrUnexpectedEOF
	}
	return nil
}
