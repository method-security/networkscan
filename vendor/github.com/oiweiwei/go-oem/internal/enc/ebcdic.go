package enc

import "github.com/indece-official/go-ebcdic"

// EBCDIC wraps the go-ebcdic library to provide the Encode/Decode methods for
// IBM EBCDIC code pages. codePage must be one of the EBCDIC* constants defined
// by that package (e.g. ebcdic.EBCDIC037).
type EBCDIC struct {
	codePage int
}

// NewEBCDIC returns an EBCDIC encoding for the given code page identifier.
func NewEBCDIC(codePage int) *EBCDIC {
	return &EBCDIC{codePage: codePage}
}

// Encode converts s from UTF-8 to the EBCDIC byte representation.
func (e EBCDIC) Encode(s string) ([]byte, error) {
	return ebcdic.Encode(s, e.codePage)
}

// Decode converts b from the EBCDIC byte representation to UTF-8.
func (e EBCDIC) Decode(b []byte) (string, error) {
	return ebcdic.Decode(b, e.codePage)
}
