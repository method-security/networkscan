package enc

import "unicode"

// Charmap2 is an Encoding backed by an explicit 256-entry rune table. It is
// used for code pages not covered by golang.org/x/text. The mapping tables are
// generated from Unicode.org character mapping files via maketables.go and
// stored in tables.go.
type Charmap2 struct {
	toUTF8   [256]rune
	fromUTF8 map[rune]byte
}

// NewCharmap2 builds a Charmap2 from a 256-entry rune table where index i
// holds the Unicode code point for byte value i. Entries set to
// unicode.ReplacementChar (U+FFFD) are treated as undefined and excluded from
// the reverse (UTF-8 to byte) mapping.
func NewCharmap2(toUTF8 [256]rune) *Charmap2 {
	cm := Charmap2{toUTF8: toUTF8, fromUTF8: make(map[rune]byte)}
	for i, r := range toUTF8 {
		if r == unicode.ReplacementChar {
			continue
		}
		cm.fromUTF8[r] = byte(i)
	}
	return &cm
}

// Encode converts s from UTF-8 to the code page byte representation.
// Runes with no mapping are replaced with 0x1A (ASCII SUB).
func (c Charmap2) Encode(s string) ([]byte, error) {
	runes := []rune(s)
	out := make([]byte, len(runes))
	for i, r := range runes {
		b, ok := c.fromUTF8[r]
		if !ok {
			b = 0x1A
		}
		out[i] = b
	}
	return out, nil
}

// Decode converts b from the code page byte representation to UTF-8.
func (c Charmap2) Decode(b []byte) (string, error) {
	out := make([]rune, len(b))
	for i, v := range b {
		out[i] = c.toUTF8[v]
	}
	return string(out), nil
}
