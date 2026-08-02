package ndr

import (
	"fmt"
	"reflect"
)

// validatePipeElementType enforces C706 §14.3.14: a pipe's base type must not
// be a conformant or varying array, or a struct containing one. The element
// type passed in is the pipe's element type (the slice's element type).
func validatePipeElementType(t reflect.Type) error {
	switch t.Kind() {
	case reflect.Slice:
		return fmt.Errorf("pipe base type cannot be a conformant or varying array")
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			ft := parseTags(t.Field(i).Tag)
			if ft.HasValue(TagConformant) || ft.HasValue(TagVarying) || ft.HasValue(TagPipe) {
				return fmt.Errorf("pipe base type cannot contain a conformant or varying field: %s.%s", t.Name(), t.Field(i).Name)
			}
			if err := validatePipeElementType(t.Field(i).Type); err != nil {
				return err
			}
		}
	case reflect.Array:
		return validatePipeElementType(t.Elem())
	}
	return nil
}

func (enc *Encoder) writePipe(v reflect.Value, tag reflect.StructTag) error {
	if err := validatePipeElementType(v.Type().Elem()); err != nil {
		return fmt.Errorf("invalid pipe element type: %v", err)
	}
	n := v.Len()
	if n > 0 {
		// Write all elements as a single chunk
		err := enc.writeUint32(uint32(n))
		if err != nil {
			return fmt.Errorf("could not write pipe chunk count: %v", err)
		}
		for i := 0; i < n; i++ {
			err := enc.fill(v.Index(i), tag, &[]deferedPtr{})
			if err != nil {
				return fmt.Errorf("could not write element %d of pipe: %v", i, err)
			}
		}
	}
	// Write terminating zero-length chunk
	return enc.writeUint32(0)
}

func (dec *Decoder) fillPipe(v reflect.Value, tag reflect.StructTag) error {
	if err := validatePipeElementType(v.Type().Elem()); err != nil {
		return fmt.Errorf("invalid pipe element type: %v", err)
	}
	s, err := dec.readUint32() // read element count of first chunk
	if err != nil {
		return err
	}
	a := reflect.MakeSlice(v.Type(), 0, 0)
	c := reflect.MakeSlice(v.Type(), int(s), int(s))
	for s != 0 {
		for i := 0; i < int(s); i++ {
			err := dec.fill(c.Index(i), tag, &[]deferedPtr{})
			if err != nil {
				return fmt.Errorf("could not fill element %d of pipe: %v", i, err)
			}
		}
		s, err = dec.readUint32() // read element count of first chunk
		if err != nil {
			return err
		}
		a = reflect.AppendSlice(a, c)
		c = reflect.MakeSlice(v.Type(), int(s), int(s))
	}
	v.Set(a)
	return nil
}
