// Package oem provides encoders and decoders for OEM (Original Equipment
// Manufacturer) code pages, including DOS, Windows, IBM EBCDIC, and CJK
// encodings.
//
// Each encoding is exposed as a package-level variable of type func() Encoding.
// Call the variable to obtain an Encoding instance:
//
//	enc := oem.CP850_DOSLatin1()
//	b, err := enc.Encode("cafe")
//
// The package also exposes top-level Encode and Decode helpers that operate on
// the default encoding (CP437 unless overridden with WithDefaultEncoding).
package oem

import (
	"context"
	"sync"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"

	"github.com/indece-official/go-ebcdic"

	"github.com/oiweiwei/go-oem/internal/enc"
)

// Encoding is the interface implemented by all OEM encodings. It provides
// bidirectional conversion between Go strings (UTF-8) and the encoded byte
// representation of a specific code page.
type Encoding interface {
	// Encode converts a UTF-8 string to the code page byte representation.
	// Characters that have no mapping in the target encoding are replaced
	// with the ASCII SUB character (0x1A).
	Encode(string) ([]byte, error)
	// Decode converts a code page byte slice to a UTF-8 string.
	// Bytes with no defined mapping are replaced with the Unicode replacement
	// character (U+FFFD).
	Decode([]byte) (string, error)
}

// Predefined OEM encoding factories. Each variable is a function that returns
// a new Encoding instance for the corresponding code page.
var (
	// ASCII is 7-bit ASCII. Non-ASCII runes are replaced with 0x1A on encode.
	ASCII = func() Encoding { return enc.ASCII{} }
	// CP437_DOSLatinUS is IBM/DOS Code Page 437 (DOS Latin US). This is the
	// default encoding used by the top-level Encode and Decode functions.
	CP437_DOSLatinUS = func() Encoding { return enc.NewCharmap(charmap.CodePage437) }
	// CP500_IBMInternational is IBM Code Page 500, an EBCDIC encoding used for
	// international IBM mainframe applications.
	CP500_IBMInternational = func() Encoding { return enc.NewEBCDIC(ebcdic.EBCDIC500) }
	// CP737_DOSGreek is DOS Code Page 737 (DOS Greek).
	CP737_DOSGreek = func() Encoding { return enc.NewCharmap2(enc.CP737_DOSGreek) }
	// CP775_DOSBaltRim is DOS Code Page 775 (DOS Baltic Rim).
	CP775_DOSBaltRim = func() Encoding { return enc.NewCharmap2(enc.CP775_DOSBaltRim) }
	// CP850_DOSLatin1 is DOS Code Page 850 (DOS Latin 1 / Western European).
	CP850_DOSLatin1 = func() Encoding { return enc.NewCharmap(charmap.CodePage850) }
	// CP852_DOSLatin2 is DOS Code Page 852 (DOS Latin 2 / Central European).
	CP852_DOSLatin2 = func() Encoding { return enc.NewCharmap(charmap.CodePage852) }
	// CP855_DOSCyrillic is DOS Code Page 855 (DOS Cyrillic).
	CP855_DOSCyrillic = func() Encoding { return enc.NewCharmap(charmap.CodePage855) }
	// CP857_DOSTurkish is DOS Code Page 857 (DOS Turkish).
	CP857_DOSTurkish = func() Encoding { return enc.NewCharmap2(enc.CP857_DOSTurkish) }
	// CP860_DOSPortuguese is DOS Code Page 860 (DOS Portuguese).
	CP860_DOSPortuguese = func() Encoding { return enc.NewCharmap(charmap.CodePage860) }
	// CP861_DOSIcelandic is DOS Code Page 861 (DOS Icelandic).
	CP861_DOSIcelandic = func() Encoding { return enc.NewCharmap2(enc.CP861_DOSIcelandic) }
	// CP862_DOSHebrew is DOS Code Page 862 (DOS Hebrew).
	CP862_DOSHebrew = func() Encoding { return enc.NewCharmap(charmap.CodePage862) }
	// CP863_DOSCanadaF is DOS Code Page 863 (DOS Canadian French).
	CP863_DOSCanadaF = func() Encoding { return enc.NewCharmap(charmap.CodePage863) }
	// CP864_DOSArabic is DOS Code Page 864 (DOS Arabic).
	CP864_DOSArabic = func() Encoding { return enc.NewCharmap2(enc.CP864_DOSArabic) }
	// CP865_DOSNordic is DOS Code Page 865 (DOS Nordic).
	CP865_DOSNordic = func() Encoding { return enc.NewCharmap(charmap.CodePage863) }
	// CP866_DOSCyrillicRussian is DOS Code Page 866 (DOS Cyrillic Russian).
	CP866_DOSCyrillicRussian = func() Encoding { return enc.NewCharmap(charmap.CodePage866) }
	// CP869_DOSGreek2 is DOS Code Page 869 (DOS Greek 2).
	CP869_DOSGreek2 = func() Encoding { return enc.NewCharmap2(enc.CP869_DOSGreek2) }
	// CP874_DOSThai is DOS/Windows Code Page 874 (Thai).
	CP874_DOSThai = func() Encoding { return enc.NewCharmap2(enc.CP874) }
	// CP875_IBMGreek is IBM Code Page 875 (IBM Greek, EBCDIC-based).
	CP875_IBMGreek = func() Encoding { return enc.NewCharmap2(enc.CP875_IBMGreek) }
	// CP932 is Windows Code Page 932 (Japanese Shift-JIS).
	CP932 = func() Encoding { return enc.NewCharmap(japanese.ShiftJIS) }
	// CP936 is Windows Code Page 936 (Simplified Chinese GBK).
	CP936 = func() Encoding { return enc.NewCharmap(simplifiedchinese.GBK) }
	// CP949 is Windows Code Page 949 (Korean EUC-KR).
	CP949 = func() Encoding { return enc.NewCharmap(korean.EUCKR) }
	// CP950 is Windows Code Page 950 (Traditional Chinese Big5).
	CP950 = func() Encoding { return enc.NewCharmap(traditionalchinese.Big5) }
	// CP1026_IBMLatin5Turkish is IBM Code Page 1026 (IBM Latin-5 Turkish, EBCDIC-based).
	CP1026_IBMLatin5Turkish = func() Encoding { return enc.NewCharmap2(enc.CP1026_IBMLatin5Turkish) }
	// CP1250 is Windows Code Page 1250 (Windows Central European).
	CP1250 = func() Encoding { return enc.NewCharmap(charmap.Windows1250) }
	// CP1251 is Windows Code Page 1251 (Windows Cyrillic).
	CP1251 = func() Encoding { return enc.NewCharmap(charmap.Windows1251) }
	// CP1252 is Windows Code Page 1252 (Windows Western European / Latin 1).
	CP1252 = func() Encoding { return enc.NewCharmap(charmap.Windows1252) }
	// EBCDIC037 is IBM EBCDIC Code Page 037 (US/Canada).
	EBCDIC037 = func() Encoding { return enc.NewEBCDIC(ebcdic.EBCDIC037) }
	// EBCDIC1140 is IBM EBCDIC Code Page 1140 (US/Canada with Euro sign).
	EBCDIC1140 = func() Encoding { return enc.NewEBCDIC(ebcdic.EBCDIC1140) }
	// EBCDIC1141 is IBM EBCDIC Code Page 1141 (Germany/Austria with Euro sign).
	EBCDIC1141 = func() Encoding { return enc.NewEBCDIC(ebcdic.EBCDIC1141) }
	// EBCDIC1148 is IBM EBCDIC Code Page 1148 (International with Euro sign).
	EBCDIC1148 = func() Encoding { return enc.NewEBCDIC(ebcdic.EBCDIC1148) }
	// EBCDIC273 is IBM EBCDIC Code Page 273 (Germany/Austria).
	EBCDIC273 = func() Encoding { return enc.NewEBCDIC(ebcdic.EBCDIC273) }
	// EBCDIC500 is IBM EBCDIC Code Page 500 (International).
	EBCDIC500 = func() Encoding { return enc.NewEBCDIC(ebcdic.EBCDIC500) }
)

var (
	defaultEncodingMu = new(sync.Mutex)
	defaultEncoding   = CP437_DOSLatinUS()
)

// DefaultEncoding returns the current package-level default encoding.
// It is safe for concurrent use. The default is CP437_DOSLatinUS unless
// changed with WithDefaultEncoding.
func DefaultEncoding() Encoding {
	return defaultEncoding
}

// WithDefaultEncoding sets the package-level default encoding used by the
// top-level Encode and Decode functions. It is safe for concurrent use.
func WithDefaultEncoding(e Encoding) {
	defaultEncodingMu.Lock()
	defaultEncoding = e
	defaultEncodingMu.Unlock()
}

// Encode encodes s using the package-level default encoding.
func Encode(s string) ([]byte, error) {
	return defaultEncoding.Encode(s)
}

// Decode decodes b using the package-level default encoding.
func Decode(b []byte) (string, error) {
	return defaultEncoding.Decode(b)
}

type ctxKey struct{}

// WithContext returns a copy of ctx carrying the given encoding. Use
// FromContext to retrieve it in downstream code.
func WithContext(ctx context.Context, e Encoding) context.Context {
	return context.WithValue(ctx, ctxKey{}, e)
}

// FromContext returns the Encoding stored in ctx by WithContext. If no encoding
// is present, the package-level default encoding is returned.
func FromContext(ctx context.Context) Encoding {
	e, ok := ctx.Value(ctxKey{}).(Encoding)
	if !ok {
		return defaultEncoding
	}
	return e
}
