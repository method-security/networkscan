package ndr

import (
	"reflect"
)

// DefaultMaxElements is the default upper bound on the number of elements the
// decoder will allocate for a single array, string or pipe. Counts are read
// directly from the byte stream, so without a bound a hostile or corrupt peer
// can make the decoder allocate an arbitrary amount of memory: a 4-byte
// max_count of 0xFFFFFFFF asks for a 16GB slice. Go treats an allocation that
// large as a fatal runtime error, which recover() cannot intercept, so the
// bound has to be applied before the allocation is attempted.
//
// Use Decoder.SetMaxElements to raise or lower it.
const DefaultMaxElements = 1 << 24

// maxTypeWalkDepth bounds the recursion in minWireSize so that a
// self-referential Go type cannot overflow the stack.
const maxTypeWalkDepth = 32

// byteLengther is implemented by the byte-backed readers in the standard
// library (*bytes.Reader, *bytes.Buffer, *strings.Reader). When the decoder is
// fed one of these the exact number of bytes left in the stream is known, which
// gives a far tighter bound on a plausible element count than DefaultMaxElements.
type byteLengther interface {
	Len() int
}

// minWireSize returns a lower bound, in octets, on the NDR representation of a
// single value of type t. It is deliberately conservative: it never
// over-estimates, so it can only ever under-reject. Alignment gaps are ignored
// and every count-prefixed construct is assumed to carry zero elements.
func minWireSize(t reflect.Type, depth int) int {
	if depth > maxTypeWalkDepth {
		return 1
	}
	switch t.Kind() {
	case reflect.Bool, reflect.Uint8, reflect.Int8:
		return 1
	case reflect.Uint16, reflect.Int16:
		return SizeUint16
	case reflect.Uint32, reflect.Int32, reflect.Float32:
		return SizeUint32
	case reflect.Uint64, reflect.Int64, reflect.Float64:
		return SizeUint64
	case reflect.String:
		// A varying string always carries offset + actual_count.
		return 2 * SizeUint32
	case reflect.Ptr:
		return SizePtr
	case reflect.Slice:
		// At least one count precedes the (possibly empty) element data.
		return SizeUint32
	case reflect.Array:
		if n := t.Len() * minWireSize(t.Elem(), depth+1); n > 0 {
			return n
		}
		return 1
	case reflect.Struct:
		total := 0
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue // unexported: not part of the wire representation
			}
			ndrTag := parseTags(f.Tag)
			if ndrTag.HasValue(TagPointer) || ndrTag.HasValue(TagFullPointer) {
				// Only the referent ID is inline; the referent is deferred.
				total += SizePtr
				continue
			}
			total += minWireSize(f.Type, depth+1)
		}
		if total > 0 {
			return total
		}
		return 1
	}
	return 1
}

// remaining reports how many bytes are left in the stream, if that is knowable.
// bufio may already have pulled some of the source into its own buffer, so both
// halves are counted.
func (dec *Decoder) remaining() (int, bool) {
	if l, ok := dec.src.(byteLengther); ok {
		return dec.r.Buffered() + l.Len(), true
	}
	return 0, false
}

// checkAllocCount validates an element count read from the byte stream before
// it is used to size an allocation.
func (dec *Decoder) checkAllocCount(n uint64, elem reflect.Type, what string) error {
	if n > uint64(dec.maxElements) {
		return Errorf("%s element count %d exceeds the maximum of %d (raise it with Decoder.SetMaxElements)",
			what, n, dec.maxElements)
	}
	if rem, ok := dec.remaining(); ok {
		if need := n * uint64(minWireSize(elem, 0)); need > uint64(rem) {
			return Errorf("%s of %d elements requires at least %d bytes but only %d remain in the stream",
				what, n, need, rem)
		}
	}
	return nil
}

// checkElementTotal applies only the configured element bound. It is for totals
// accumulated across several reads, where the bytes backing the earlier reads
// have already been consumed and so no longer show up in remaining().
func (dec *Decoder) checkElementTotal(n uint64, what string) error {
	if n > uint64(dec.maxElements) {
		return Errorf("%s element count %d exceeds the maximum of %d (raise it with Decoder.SetMaxElements)",
			what, n, dec.maxElements)
	}
	return nil
}

// checkAllocDims validates the per-dimension counts of a multi-dimensional
// array. Both the individual counts and their product matter: the product is
// the number of elements allocated, and it is also the size of the index
// permutation table built to walk them.
func (dec *Decoder) checkAllocDims(dims []uint64, elem reflect.Type, what string) error {
	total := uint64(1)
	for _, d := range dims {
		if d > uint64(dec.maxElements) {
			return Errorf("%s dimension count %d exceeds the maximum of %d (raise it with Decoder.SetMaxElements)",
				what, d, dec.maxElements)
		}
		if d == 0 {
			total = 0
			continue
		}
		if total > uint64(dec.maxElements)/d {
			return Errorf("%s dimensions %v overflow the maximum element count of %d (raise it with Decoder.SetMaxElements)",
				what, dims, dec.maxElements)
		}
		total *= d
	}
	return dec.checkAllocCount(total, elem, what)
}
