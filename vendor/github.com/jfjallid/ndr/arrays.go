package ndr

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
)

// typeAlignment returns the NDR alignment requirement for a Go type.
// Per NDR spec, primitives align to their size; structs align to the max
// alignment of their fields; arrays/strings/pointers align to 4 (uint32
// metadata). For structs with unionTag fields, union alignment rules apply
// (max of tag and all arms).
func typeAlignment(t reflect.Type) int {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Bool, reflect.Uint8, reflect.Int8:
		return 1
	case reflect.Uint16, reflect.Int16:
		return 2
	case reflect.Uint32, reflect.Int32, reflect.Float32:
		return 4
	case reflect.Uint64, reflect.Int64, reflect.Float64:
		return 8
	case reflect.String:
		return 4 // strings start with uint32 metadata
	case reflect.Slice, reflect.Array:
		// arrays have uint32 metadata (offset/count); element type may need higher alignment
		elemAlign := typeAlignment(t.Elem())
		if elemAlign < 4 {
			return 4
		}
		return elemAlign
	case reflect.Struct:
		return structAlignment(t)
	default:
		return 1
	}
}

// structAlignment returns the NDR alignment of a struct type, which is the
// largest alignment of any of its fields. For a non-encapsulated union
// struct the alignment is the discriminator's alignment alone (per C706
// §14.3.9); arm alignment is internal to the union body and does not pad
// the union externally.
//
// Invariant: for encapsulated unions this function relies on every union arm
// being a regular struct field (with a `unionField` tag). The "max of all
// fields" walk then naturally yields max(discriminator, all arms) as C706
// §14.3.9 requires. If arms ever become non-field-backed (e.g., synthesized
// from a method), encapsulated-union external alignment must be computed
// explicitly here.
func structAlignment(t reflect.Type) int {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return 1
	}
	if a := nonEncapUnionDiscAlignment(t); a > 0 {
		return a
	}
	maxAlign := 1
	for i := 0; i < t.NumField(); i++ {
		ft := t.Field(i).Type
		// Fields tagged as pointers have alignment 4 (referent ID), not the
		// alignment of the pointed-to type (which is deferred).
		ndrTag := parseTags(t.Field(i).Tag)
		var a int
		if ndrTag.HasValue(TagPointer) || ndrTag.HasValue(TagFullPointer) {
			a = 4
		} else {
			a = typeAlignment(ft)
		}
		if a > maxAlign {
			maxAlign = a
		}
	}
	return maxAlign
}

// intFromTag returns an int that is a value in a struct tag key/value pair
func intFromTag(tag reflect.StructTag, key string) (int, error) {
	ndrTag := parseTags(tag)
	d := 1
	if n, ok := ndrTag.Map[key]; ok {
		i, err := strconv.Atoi(n)
		if err != nil {
			return d, fmt.Errorf("invalid dimensions tag [%s]: %v", n, err)
		}
		d = i
	}
	return d, nil
}

// parseDimensions returns the a slice of the size of each dimension and type of the member at the deepest level.
func parseDimensions(v reflect.Value) (l []int, tb reflect.Type) {
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	t := v.Type()
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Array && t.Kind() != reflect.Slice {
		return
	}
	l = append(l, v.Len())
	if t.Elem().Kind() == reflect.Array || t.Elem().Kind() == reflect.Slice {
		// contains array or slice
		var m []int
		m, tb = parseDimensions(v.Index(0))
		l = append(l, m...)
	} else {
		tb = t.Elem()
	}
	return
}

// sliceDimensions returns the count of dimensions a slice has.
func sliceDimensions(t reflect.Type) (d int, tb reflect.Type) {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() == reflect.Slice {
		d++
		var n int
		n, tb = sliceDimensions(t.Elem())
		d += n
	} else {
		tb = t
	}
	return
}

// makeSubSlices is a deep recursive creation/initialisation of multi-dimensional slices.
// Takes the reflect.Value of the 1st dimension and a slice of the lengths of the sub dimensions
func makeSubSlices(v reflect.Value, l []int) {
	ty := v.Type().Elem()
	if ty.Kind() != reflect.Slice {
		return
	}
	for i := 0; i < v.Len(); i++ {
		s := reflect.MakeSlice(ty, l[0], l[0])
		v.Index(i).Set(s)
		// Are there more sub dimensions?
		if len(l) > 1 {
			makeSubSlices(v.Index(i), l[1:])
		}
	}
	return
}

// multiDimensionalIndexPermutations returns all the permutations of the indexes of a multi-dimensional slice.
// The input is a slice of integers that indicates the max size/length of each dimension
func multiDimensionalIndexPermutations(l []int) (ps [][]int) {
	z := make([]int, len(l), len(l)) // The zeros permutation
	ps = append(ps, z)
	// for each dimension, in reverse
	for i := len(l) - 1; i >= 0; i-- {
		ws := make([][]int, len(ps))
		copy(ws, ps)
		//create a permutation for each of the iterations of the current dimension
		for j := 1; j <= l[i]-1; j++ {
			// For each existing permutation
			for _, p := range ws {
				np := make([]int, len(p), len(p))
				copy(np, p)
				np[i] = j
				ps = append(ps, np)
			}
		}
	}
	return
}

// precedingMax reads off the next conformant max value
func (dec *Decoder) precedingMax() uint32 {
	m := dec.conformantMax[0]
	dec.conformantMax = dec.conformantMax[1:]
	return m
}

// precedingMax reads off the next conformant max value
func (enc *Encoder) precedingMax() uint32 {
	m := enc.conformantMax[0]
	enc.conformantMax = enc.conformantMax[1:]
	return m
}

// fillFixedArray establishes if the fixed array is uni or multi dimensional and then fills it.
func (dec *Decoder) fillFixedArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	l, t := parseDimensions(v)
	if t.Kind() == reflect.String {
		tag = reflect.StructTag(subStringArrayTag)
	}
	if len(l) < 1 {
		return errors.New("could not establish dimensions of fixed array")
	}
	if len(l) == 1 {
		err := dec.fillUniDimensionalFixedArray(v, tag, def)
		if err != nil {
			return fmt.Errorf("could not fill uni-dimensional fixed array: %v", err)
		}
		return nil
	}
	// Fixed array is multidimensional
	ps := multiDimensionalIndexPermutations(l[:len(l)-1])
	for _, p := range ps {
		// Get current multi-dimensional index to fill
		a := v
		for _, i := range p {
			a = a.Index(i)
		}
		// fill with the last dimension array
		err := dec.fillUniDimensionalFixedArray(a, tag, def)
		if err != nil {
			return fmt.Errorf("could not fill dimension %v of multi-dimensional fixed array: %v", p, err)
		}
	}
	return nil
}

// readUniDimensionalFixedArray reads an array (not slice) from the byte stream.
func (dec *Decoder) fillUniDimensionalFixedArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	for i := 0; i < v.Len(); i++ {
		err := dec.fill(v.Index(i), tag, def)
		if err != nil {
			return fmt.Errorf("could not fill index %d of fixed array: %v", i, err)
		}
	}
	return nil
}

// fillConformantArray establishes if the conformant array is uni or multi dimensional and then fills the slice.
func (dec *Decoder) fillConformantArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	d, _ := sliceDimensions(v.Type())
	if d > 1 {
		err := dec.fillMultiDimensionalConformantArray(v, d, tag, def)
		if err != nil {
			return err
		}
	} else {
		err := dec.fillUniDimensionalConformantArray(v, tag, def)
		if err != nil {
			return err
		}
	}
	return nil
}

// fillUniDimensionalConformantArray fills the uni-dimensional slice value.
func (dec *Decoder) fillUniDimensionalConformantArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	m := dec.precedingMax()
	n := int(m)
	//fmt.Printf("Encountered conformant array with max count: %d for field: %v\n", m, dec.current)
	a := reflect.MakeSlice(v.Type(), n, n)
	for i := 0; i < n; i++ {
		err := dec.fill(a.Index(i), tag, def)
		if err != nil {
			return fmt.Errorf("could not fill index %d of uni-dimensional conformant array: %v", i, err)
		}
	}
	v.Set(a)
	return nil
}

// fillMultiDimensionalConformantArray fills the multi-dimensional slice value provided from conformant array data.
// The number of dimensions must be specified. This must be less than or equal to the dimensions in the slice for this
// method not to panic.
func (dec *Decoder) fillMultiDimensionalConformantArray(v reflect.Value, d int, tag reflect.StructTag, def *[]deferedPtr) error {
	// Read the max size of each dimensions from the ndr stream
	l := make([]int, d, d)
	for i := range l {
		l[i] = int(dec.precedingMax())
	}
	// Initialise size of slices
	//   Initialise the size of the 1st dimension
	ty := v.Type()
	v.Set(reflect.MakeSlice(ty, l[0], l[0]))
	// Initialise the size of the other dimensions recursively
	makeSubSlices(v, l[1:])

	// Get all permutations of the indexes and go through each and fill
	ps := multiDimensionalIndexPermutations(l)
	for _, p := range ps {
		// Get current multi-dimensional index to fill
		a := v
		for _, i := range p {
			a = a.Index(i)
		}
		err := dec.fill(a, tag, def)
		if err != nil {
			return fmt.Errorf("could not fill index %v of slice: %v", p, err)
		}
	}
	return nil
}

// fillVaryingArray establishes if the varying array is uni or multi dimensional and then fills the slice.
func (dec *Decoder) fillVaryingArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	d, t := sliceDimensions(v.Type())
	if d > 1 {
		err := dec.fillMultiDimensionalVaryingArray(v, t, d, tag, def)
		if err != nil {
			return err
		}
	} else {
		err := dec.fillUniDimensionalVaryingArray(v, tag, def)
		if err != nil {
			return err
		}
	}
	return nil
}

// fillUniDimensionalVaryingArray fills the uni-dimensional slice value.
func (dec *Decoder) fillUniDimensionalVaryingArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	o, err := dec.readUint32()
	if err != nil {
		return fmt.Errorf("could not read offset of uni-dimensional varying array: %v", err)
	}
	s, err := dec.readUint32()
	if err != nil {
		return fmt.Errorf("could not establish actual count of uni-dimensional varying array: %v", err)
	}
	t := v.Type()
	// Total size of the array is the offset in the index being passed plus the actual count of elements being passed.
	n := int(s + o)
	a := reflect.MakeSlice(t, n, n)
	// Populate the array starting at the offset specified
	for i := int(o); i < n; i++ {
		err := dec.fill(a.Index(i), tag, def)
		if err != nil {
			return fmt.Errorf("could not fill index %d of uni-dimensional varying array: %v", i, err)
		}
	}
	v.Set(a)
	return nil
}

// fillMultiDimensionalVaryingArray fills the multi-dimensional slice value provided from varying array data.
// The number of dimensions must be specified. This must be less than or equal to the dimensions in the slice for this
// method not to panic.
func (dec *Decoder) fillMultiDimensionalVaryingArray(v reflect.Value, t reflect.Type, d int, tag reflect.StructTag, def *[]deferedPtr) error {
	// Read the offset and actual count of each dimensions from the ndr stream
	o := make([]int, d, d)
	l := make([]int, d, d)
	for i := range l {
		off, err := dec.readUint32()
		if err != nil {
			return fmt.Errorf("could not read offset of dimension %d: %v", i+1, err)
		}
		o[i] = int(off)
		s, err := dec.readUint32()
		if err != nil {
			return fmt.Errorf("could not read size of dimension %d: %v", i+1, err)
		}
		l[i] = int(s) + int(off)
	}
	// Initialise size of slices
	//   Initialise the size of the 1st dimension
	ty := v.Type()
	v.Set(reflect.MakeSlice(ty, l[0], l[0]))
	// Initialise the size of the other dimensions recursively
	makeSubSlices(v, l[1:])

	// Get all permutations of the indexes and go through each and fill
	ps := multiDimensionalIndexPermutations(l)
	for _, p := range ps {
		// Get current multi-dimensional index to fill
		a := v
		var os bool // should this permutation be skipped due to the offset of any of the dimensions?
		for i, j := range p {
			if j < o[i] {
				os = true
				break
			}
			a = a.Index(j)
		}
		if os {
			// This permutation should be skipped as it is less than the offset for one of the dimensions.
			continue
		}
		err := dec.fill(a, tag, def)
		if err != nil {
			return fmt.Errorf("could not fill index %v of slice: %v", p, err)
		}
	}
	return nil
}

// fillConformantVaryingArray establishes if the varying array is uni or multi dimensional and then fills the slice.
func (dec *Decoder) fillConformantVaryingArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	d, t := sliceDimensions(v.Type())
	if d > 1 {
		err := dec.fillMultiDimensionalConformantVaryingArray(v, t, d, tag, def)
		if err != nil {
			return err
		}
	} else {
		err := dec.fillUniDimensionalConformantVaryingArray(v, tag, def)
		if err != nil {
			return err
		}
	}
	return nil
}

// fillUniDimensionalConformantVaryingArray fills the uni-dimensional slice value.
// Per C706 §14.3.7.2: the wire carries `actual_count` (s) elements placed at
// positions [offset, offset+actual_count). The first `offset` slots are
// zero-valued placeholders, matching the varying-only sibling.
func (dec *Decoder) fillUniDimensionalConformantVaryingArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	m := dec.precedingMax()
	o, err := dec.readUint32()
	if err != nil {
		return fmt.Errorf("could not read offset of uni-dimensional conformant varying array: %v", err)
	}
	s, err := dec.readUint32()
	if err != nil {
		return fmt.Errorf("could not establish actual count of uni-dimensional conformant varying array: %v", err)
	}
	if m < o+s {
		return errors.New("max count is less than the offset plus actual count")
	}
	t := v.Type()
	n := int(s + o)
	a := reflect.MakeSlice(t, n, n)
	for i := int(o); i < n; i++ {
		err := dec.fill(a.Index(i), tag, def)
		if err != nil {
			return fmt.Errorf("could not fill index %d of uni-dimensional conformant varying array: %v", i, err)
		}
	}
	v.Set(a)
	return nil
}

// fillMultiDimensionalConformantVaryingArray fills the multi-dimensional slice value provided from conformant varying array data.
// The number of dimensions must be specified. This must be less than or equal to the dimensions in the slice for this
// method not to panic.
func (dec *Decoder) fillMultiDimensionalConformantVaryingArray(v reflect.Value, t reflect.Type, d int, tag reflect.StructTag, def *[]deferedPtr) error {
	// Read the offset and actual count of each dimensions from the ndr stream.
	// Per C706 §14.3.7.2, max_count >= actual_count + offset; transmitted
	// elements occupy indices [offset, offset+actual_count). Slice size matches
	// the transmitted range (actual+offset), like the uni-dim sibling.
	m := make([]int, d)
	for i := range m {
		m[i] = int(dec.precedingMax())
	}
	o := make([]int, d)
	l := make([]int, d)
	for i := range l {
		off, err := dec.readUint32()
		if err != nil {
			return fmt.Errorf("could not read offset of dimension %d: %v", i+1, err)
		}
		o[i] = int(off)
		s, err := dec.readUint32()
		if err != nil {
			return fmt.Errorf("could not read actual count of dimension %d: %v", i+1, err)
		}
		if m[i] < int(s)+int(off) {
			return fmt.Errorf("max count %d is less than offset %d plus actual count %d for dimension %d", m[i], off, s, i+1)
		}
		l[i] = int(s) + int(off)
	}
	// Initialise size of slices
	//   Initialise the size of the 1st dimension
	ty := v.Type()
	v.Set(reflect.MakeSlice(ty, l[0], l[0]))
	// Initialise the size of the other dimensions recursively
	makeSubSlices(v, l[1:])

	// Get all permutations of the indexes and go through each and fill
	ps := multiDimensionalIndexPermutations(l)
	for _, p := range ps {
		// Get current multi-dimensional index to fill
		a := v
		var os bool // should this permutation be skipped due to the offset of any of the dimensions
		for i, j := range p {
			if j < o[i] {
				os = true
				break
			}
			a = a.Index(j)
		}
		if os {
			// This permutation should be skipped as it is less than the offset for one of the dimensions.
			continue
		}
		err := dec.fill(a, tag, def)
		if err != nil {
			return fmt.Errorf("could not fill index %v of slice: %v", p, err)
		}
	}
	return nil
}

func (enc *Encoder) writeFixedArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	l, t := parseDimensions(v)
	if t.Kind() == reflect.String {
		tag = reflect.StructTag(subStringArrayTag)
	}
	if len(l) < 1 {
		return errors.New("could not establish dimensions of fixed array")
	}
	if len(l) == 1 {
		err := enc.writeUniDimensionalFixedArray(v, tag, def)
		if err != nil {
			return fmt.Errorf("could not fill uni-dimensional fixed array: %v", err)
		}
		return nil
	}
	// Fixed array is multidimensional
	ps := multiDimensionalIndexPermutations(l[:len(l)-1])
	for _, p := range ps {
		// Get current multi-dimensional index to write
		a := v
		for _, i := range p {
			a = a.Index(i)
		}
		// write the last dimension array
		err := enc.writeUniDimensionalFixedArray(a, tag, def)
		if err != nil {
			return fmt.Errorf("could not write dimension %v of multi-dimensional fixed array: %v", p, err)
		}
	}
	return nil
}

func (enc *Encoder) writeUniDimensionalFixedArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	for i := 0; i < v.Len(); i++ {
		err := enc.fill(v.Index(i), tag, def)
		if err != nil {
			return fmt.Errorf("could not fill index %d of fixed array: %v", i, err)
		}
	}
	return nil
}

func (enc *Encoder) writeConformantArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	d, _ := sliceDimensions(v.Type())
	if d > 1 {
		err := enc.writeMultiDimensionalConformantArray(v, d, tag, def)
		if err != nil {
			return err
		}
	} else {
		err := enc.writeUniDimensionalFixedArray(v, tag, def)
		if err != nil {
			return err
		}
	}
	return nil
}

func (enc *Encoder) writeMultiDimensionalConformantArray(v reflect.Value, d int, tag reflect.StructTag, def *[]deferedPtr) error {
	// Max values were already written by process()/conformantScan(). Get dimensions from the value.
	l, _ := parseDimensions(v)

	// Get all permutations of the indexes and write each element
	ps := multiDimensionalIndexPermutations(l)
	for _, p := range ps {
		a := v
		for _, i := range p {
			a = a.Index(i)
		}
		err := enc.fill(a, tag, def)
		if err != nil {
			return fmt.Errorf("could not write index %v of multi-dimensional conformant array: %v", p, err)
		}
	}
	return nil
}

// fillVaryingArray establishes if the varying array is uni or multi dimensional and then fills the slice.
func (enc *Encoder) writeVaryingArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	d, _ := sliceDimensions(v.Type())
	if d > 1 {
		err := enc.writeMultiDimensionalVaryingArray(v, d, tag, def)
		if err != nil {
			return err
		}
	} else {
		err := enc.writeUniDimensionalVaryingArray(v, tag, def)
		if err != nil {
			return err
		}
	}
	return nil
}

func (enc *Encoder) writeMultiDimensionalVaryingArray(v reflect.Value, d int, tag reflect.StructTag, def *[]deferedPtr) error {
	// Write offset and actual count for each dimension
	l, _ := parseDimensions(v)
	for i := 0; i < d; i++ {
		// offset is always 0
		err := enc.writeUint32(uint32(0))
		if err != nil {
			return fmt.Errorf("could not write offset of dimension %d: %v", i+1, err)
		}
		err = enc.writeUint32(uint32(l[i]))
		if err != nil {
			return fmt.Errorf("could not write actual count of dimension %d: %v", i+1, err)
		}
	}

	// Get all permutations of the indexes and write each element
	ps := multiDimensionalIndexPermutations(l[:len(l)-1])
	for _, p := range ps {
		a := v
		for _, i := range p {
			a = a.Index(i)
		}
		err := enc.writeUniDimensionalFixedArray(a, tag, def)
		if err != nil {
			return fmt.Errorf("could not write dimension %v of multi-dimensional varying array: %v", p, err)
		}
	}
	return nil
}

// writeUniDimensionalVaryingArray writes the uni-dimensional slice value.
func (enc *Encoder) writeUniDimensionalVaryingArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	// Use an offset of 0
	err := enc.writeUint32(uint32(0))
	if err != nil {
		return fmt.Errorf("could not write offset of uni-dimensional varying array: %v", err)
	}
	err = enc.writeUint32(uint32(v.Len()))
	if err != nil {
		return fmt.Errorf("could not write actual count of uni-dimensional varying array: %v", err)
	}
	err = enc.writeUniDimensionalFixedArray(v, tag, def)
	if err != nil {
		return fmt.Errorf("could not write uni-dimensional varying array: %v", err)
	}
	return nil
}

func (enc *Encoder) writeConformantVaryingArray(v reflect.Value, tag reflect.StructTag, def *[]deferedPtr) error {
	d, _ := sliceDimensions(v.Type())
	if d > 1 {
		err := enc.writeMultiDimensionalConformantVaryingArray(v, d, tag, def)
		if err != nil {
			return err
		}
	} else {
		err := enc.writeUniDimensionalVaryingArray(v, tag, def)
		if err != nil {
			return err
		}
	}
	return nil
}

func (enc *Encoder) writeMultiDimensionalConformantVaryingArray(v reflect.Value, d int, tag reflect.StructTag, def *[]deferedPtr) error {
	// Max values were already written by process()/conformantScan(). Get dimensions from the value.
	l, _ := parseDimensions(v)

	// Write offset and actual count for each dimension
	for i := 0; i < d; i++ {
		// offset is always 0
		err := enc.writeUint32(uint32(0))
		if err != nil {
			return fmt.Errorf("could not write offset of dimension %d: %v", i+1, err)
		}
		err = enc.writeUint32(uint32(l[i]))
		if err != nil {
			return fmt.Errorf("could not write actual count of dimension %d: %v", i+1, err)
		}
	}

	// Get all permutations of the indexes and write each element
	ps := multiDimensionalIndexPermutations(l[:len(l)-1])
	for _, p := range ps {
		a := v
		for _, i := range p {
			a = a.Index(i)
		}
		err := enc.writeUniDimensionalFixedArray(a, tag, def)
		if err != nil {
			return fmt.Errorf("could not write dimension %v of multi-dimensional conformant varying array: %v", p, err)
		}
	}
	return nil
}
