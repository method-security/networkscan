package enc

import "unicode"

const asciiReplacementChar = 0x1A

// ASCII is a 7-bit ASCII encoding. Non-ASCII runes are replaced with 0x1A
// (ASCII SUB) on encode; 0x1A bytes become U+FFFD on decode.
type ASCII struct{}

// Encode converts s to ASCII bytes. Runes above U+007F are replaced with 0x1A.
func (ASCII) Encode(s string) ([]byte, error) {
	runes := []rune(s)
	b := make([]byte, len(runes))
	for i := 0; i < len(b); i++ {
		if runes[i] > unicode.MaxASCII {
			b[i] = asciiReplacementChar
		} else {
			b[i] = byte(runes[i])
		}
	}
	return b, nil
}

// Decode converts ASCII bytes to a UTF-8 string. 0x1A bytes are replaced with
// U+FFFD.
func (ASCII) Decode(b []byte) (string, error) {
	runes := make([]rune, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == asciiReplacementChar {
			runes[i] = unicode.ReplacementChar
		} else {
			runes[i] = rune(b[i])
		}
	}
	return string(runes), nil
}
