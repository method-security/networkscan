//go:build !linux

package rawsend

// Batch is not available on non-Linux platforms (no sendmmsg).
type Batch struct{}

// NewBatch returns nil on non-Linux platforms where sendmmsg
// is not available.
func NewBatch(_ socketFD, _, _ int) *Batch { return nil }

func (b *Batch) Add(_ []byte, _ [4]byte) error { return nil }
func (b *Batch) Flush() error                   { return nil }
func (b *Batch) Len() int                       { return 0 }
