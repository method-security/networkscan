# go-oem

A Go library for encoding and decoding strings using OEM (Original Equipment Manufacturer) code pages, including DOS, Windows, IBM/EBCDIC, and CJK encodings.

## Installation

```
go get github.com/oiweiwei/go-oem
```

## Usage

### Top-level encode/decode (uses CP437 by default)

```go
import "github.com/oiweiwei/go-oem"

b, err := oem.Encode("Hello")
s, err := oem.Decode(b)
```

### Change the default encoding

```go
oem.WithDefaultEncoding(oem.CP850_DOSLatin1())
```

### Use a specific encoding directly

```go
enc := oem.CP866_DOSCyrillicRussian()
b, err := enc.Encode("Привет")
s, err := enc.Decode(b)
```

### Context-scoped encoding

```go
ctx := oem.WithContext(context.Background(), oem.CP1251())
enc := oem.FromContext(ctx)
```

## Supported encodings

| Constant                   | Description                    |
|----------------------------|--------------------------------|
| `ASCII`                    | 7-bit ASCII                    |
| `CP437_DOSLatinUS`         | DOS Latin US (default)         |
| `CP500_IBMInternational`   | IBM International (EBCDIC)     |
| `CP737_DOSGreek`           | DOS Greek                      |
| `CP775_DOSBaltRim`         | DOS Baltic Rim                 |
| `CP850_DOSLatin1`          | DOS Latin 1                    |
| `CP852_DOSLatin2`          | DOS Latin 2                    |
| `CP855_DOSCyrillic`        | DOS Cyrillic                   |
| `CP857_DOSTurkish`         | DOS Turkish                    |
| `CP860_DOSPortuguese`      | DOS Portuguese                 |
| `CP861_DOSIcelandic`       | DOS Icelandic                  |
| `CP862_DOSHebrew`          | DOS Hebrew                     |
| `CP863_DOSCanadaF`         | DOS Canadian French            |
| `CP864_DOSArabic`          | DOS Arabic                     |
| `CP865_DOSNordic`          | DOS Nordic                     |
| `CP866_DOSCyrillicRussian` | DOS Cyrillic Russian           |
| `CP869_DOSGreek2`          | DOS Greek 2                    |
| `CP874_DOSThai`            | DOS Thai                       |
| `CP875_IBMGreek`           | IBM Greek                      |
| `CP932`                    | Japanese Shift-JIS             |
| `CP936`                    | Simplified Chinese GBK         |
| `CP949`                    | Korean EUC-KR                  |
| `CP950`                    | Traditional Chinese Big5       |
| `CP1026_IBMLatin5Turkish`  | IBM Latin-5 Turkish            |
| `CP1250`                   | Windows Central European       |
| `CP1251`                   | Windows Cyrillic               |
| `CP1252`                   | Windows Western European       |
| `EBCDIC037`                | EBCDIC 037                     |
| `EBCDIC273`                | EBCDIC 273                     |
| `EBCDIC500`                | EBCDIC 500                     |
| `EBCDIC1140`               | EBCDIC 1140                    |
| `EBCDIC1141`               | EBCDIC 1141                    |
| `EBCDIC1148`               | EBCDIC 1148                    |

Each constant is a factory function -- call it to get an `Encoding` instance.

## License

See [LICENSE](LICENSE).
