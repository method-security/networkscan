package ndr

import (
	"errors"
	"fmt"
)

// ErrMalformed is the sentinel every NDR decoding/encoding failure matches, so
// callers can distinguish a protocol-level problem from a transport one:
//
//	if errors.Is(err, ndr.ErrMalformed) { ... }
var ErrMalformed = errors.New("malformed NDR stream")

// Malformed implements the error interface for malformed NDR encoding errors.
type Malformed struct {
	EText string
	// Err is the underlying cause, when one was supplied via %w. It is exposed
	// through Unwrap so errors.Is/errors.As reach wrapped errors such as
	// io.ErrUnexpectedEOF.
	Err error
}

// Error implements the error interface on the Malformed struct.
func (e Malformed) Error() string {
	return fmt.Sprintf("malformed NDR stream: %s", e.EText)
}

// Unwrap exposes the wrapped cause to errors.Is and errors.As.
func (e Malformed) Unwrap() error { return e.Err }

// Is reports Malformed as matching ErrMalformed, so callers can test for any
// NDR-level failure without depending on the concrete type.
func (e Malformed) Is(target error) bool { return target == ErrMalformed }

// Errorf formats an error message into a malformed NDR error. A %w verb in the
// format is honoured: the wrapped error stays reachable via errors.Is/As.
func Errorf(format string, a ...interface{}) Malformed {
	e := fmt.Errorf(format, a...)
	return Malformed{EText: e.Error(), Err: errors.Unwrap(e)}
}
