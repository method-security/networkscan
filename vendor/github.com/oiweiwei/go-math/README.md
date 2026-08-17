# go-math

A Go library for converting floating-point values between IEEE 754 and legacy binary formats used by IBM mainframes, VAX, and Cray supercomputers.

## Formats

| Format | Variable | Float32 | Float64 |
|--------|----------|---------|---------|
| IEEE 754 | `IEEE` | standard | standard |
| IBM Hexadecimal | `IBMHex` | single-precision | double-precision |
| VAX | `Vax` | F format | G format |
| Cray NDR | `Cray` | IEEE big-endian | Cray native |

## Install

```
go get github.com/oiweiwei/go-math
```

## Usage

Each format implements the `FloatFormat` interface:

```go
type FloatFormat interface {
    Float32bits(float32) uint32
    Float32frombits(uint32) float32
    Float64bits(float64) uint64
    Float64frombits(uint64) float64
}
```

### Convert a float32 to IBM Hexadecimal bits

```go
import math "github.com/oiweiwei/go-math"

bits := math.IBMHex.Float32bits(123.45)       // float32 -> IBM hex uint32
val  := math.IBMHex.Float32frombits(bits)     // IBM hex uint32 -> float32
```

### Convert a float64 to VAX G format

```go
bits := math.Vax.Float64bits(3.141592653589793)   // float64 -> VAX G uint64
val  := math.Vax.Float64frombits(bits)            // VAX G uint64 -> float64
```

### Low-level functions

Individual conversion functions are also exported:

```go
// IBM Hexadecimal
math.IBMHexfloat32bits(v float32) uint32
math.IBMHexfloat32frombits(b uint32) float32
math.IBMHexfloat64bits(v float64) uint64
math.IBMHexfloat64frombits(b uint64) float64

// VAX F (single) and G (double)
math.VaxFfloat32bits(v float32) uint32
math.VaxFfloat32frombits(b uint32) float32
math.VaxGfloat64bits(v float64) uint64
math.VaxGfloat64frombits(b uint64) float64

// Cray NDR
math.CrayFloat32bits(v float32) uint32
math.CrayFloat32frombits(b uint32) float32
math.CrayFloat64bits(v float64) uint64
math.CrayFloat64frombits(b uint64) float64
```

## License

MIT
