package ndr

import (
	"errors"
	"fmt"
	"reflect"
)

// Union interface must be implemented by structs that will be unmarshaled into from the NDR byte stream union representation.
// The union's discriminating tag will be passed to the SwitchFunc method.
// The discriminating tag field must have the struct tag: `ndr:"unionTag"`
// If the union is encapsulated the discriminating tag field must have the struct tag: `ndr:"encapsulated"`
// The possible value fields that can be selected from must have the struct tag: `ndr:"unionField"`
type Union interface {
	SwitchFunc(t interface{}) string
}

// Union related constants such as struct tag values
const (
	unionSelectionFuncName = "SwitchFunc"
	TagEncapsulated        = "encapsulated"
	TagUnionTag            = "unionTag"
	TagUnionField          = "unionField"
)

// maxArmAlignment returns the maximum NDR alignment across all fields tagged
// as union arms (`ndr:"unionField"`) on struct type t. Per C706 §14.3.9
// (encapsulated) and §14.3.10 (non-encapsulated), the selected arm is aligned
// to max(alignment of all arms), regardless of which arm is actually selected.
// Returns 1 if t has no arm-tagged fields (no-op alignment).
func maxArmAlignment(t reflect.Type) int {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return 1
	}
	a := 1
	for i := 0; i < t.NumField(); i++ {
		ft := parseTags(t.Field(i).Tag)
		if !ft.HasValue(TagUnionField) {
			continue
		}
		if x := typeAlignment(t.Field(i).Type); x > a {
			a = x
		}
	}
	return a
}

// nonEncapUnionDiscAlignment reports the discriminator's alignment if t is a
// non-encapsulated union struct (has a field tagged `ndr:"unionTag"` without
// `encapsulated`), else 0. Per DCE 1.1 NDR (C706 §14.3.9) a non-encapsulated
// union's external alignment is its discriminator's alignment; arm alignment
// is applied internally between the discriminator and the arm, not before
// the union as a whole. Encapsulated unions (C706 §14.3.7) align to max of
// discriminator and arms — handled by the regular structAlignment path.
func nonEncapUnionDiscAlignment(t reflect.Type) int {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return 0
	}
	for i := 0; i < t.NumField(); i++ {
		tag := parseTags(t.Field(i).Tag)
		if !tag.HasValue(TagUnionTag) {
			continue
		}
		if tag.HasValue(TagEncapsulated) {
			return 0
		}
		return typeAlignment(t.Field(i).Type)
	}
	return 0
}

func (enc *Encoder) isUnion(field reflect.Value, tag reflect.StructTag) (r reflect.Value) {
	ndrTag := parseTags(tag)
	if !ndrTag.HasValue(TagUnionTag) {
		return
	}
	r = field
	// For a non-encapsulated union, the discriminant is marshalled into the transmitted data stream twice: once as the
	// field or parameter, which is referenced by the switch_is construct, in the procedure argument list; and once as
	// the first part of the union representation. The field value was already written by fill(), so write it again here.
	if !ndrTag.HasValue(TagEncapsulated) {
		enc.fill(field, reflect.StructTag(""), &[]deferedPtr{})
	}
	return
}

func (dec *Decoder) isUnion(field reflect.Value, tag reflect.StructTag) (r reflect.Value) {
	ndrTag := parseTags(tag)
	if !ndrTag.HasValue(TagUnionTag) {
		return
	}
	r = field
	// For a non-encapsulated union, the discriminant is marshalled into the transmitted data stream twice: once as the
	// field or parameter, which is referenced by the switch_is construct, in the procedure argument list; and once as
	// the first part of the union representation.
	if !ndrTag.HasValue(TagEncapsulated) {
		dec.discard(int(r.Type().Size()))
	}
	return
}

// unionSelectedField returns the field name of which of the union values to fill
func unionSelectedField(union, discriminant reflect.Value) (string, error) {
	if !union.Type().Implements(reflect.TypeOf(new(Union)).Elem()) {
		return "", errors.New("struct does not implement union interface")
	}
	args := []reflect.Value{discriminant}
	// Call the SelectFunc of the union struct to find the name of the field to fill with the value selected.
	sf := union.MethodByName(unionSelectionFuncName)
	if !sf.IsValid() {
		return "", fmt.Errorf("could not find a selection function called %s in the unions struct representation", unionSelectionFuncName)
	}
	f := sf.Call(args)
	if f[0].Kind() != reflect.String || f[0].String() == "" {
		return "", fmt.Errorf("the union select function did not return a string for the name of the field to fill")
	}
	return f[0].String(), nil
}
