package enc

import "golang.org/x/text/encoding"

// Charmap wraps an x/text encoding.Encoding to provide the Encode/Decode
// methods. It is used for code pages already provided by golang.org/x/text
// (e.g. CP437, CP850, Windows-1252).
type Charmap struct {
	enc encoding.Encoding
}

// NewCharmap returns a Charmap backed by the given x/text encoding.
func NewCharmap(e encoding.Encoding) *Charmap {
	return &Charmap{enc: e}
}

// Encode converts s from UTF-8 to the code page byte representation.
func (c Charmap) Encode(s string) ([]byte, error) {
	return c.enc.NewEncoder().Bytes([]byte(s))
}

// Decode converts b from the code page byte representation to UTF-8.
func (c Charmap) Decode(b []byte) (string, error) {
	out, err := c.enc.NewDecoder().Bytes(b)
	return string(out), err
}
