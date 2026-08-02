//go:build linux

package rawsend

import (
	"runtime"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

var sendmmsgAddr uintptr

func init() {
	libc, err := purego.Dlopen("libc.so.6", purego.RTLD_LAZY)
	if err != nil {
		return
	}
	addr, err := purego.Dlsym(libc, "sendmmsg")
	if err != nil {
		return
	}
	sendmmsgAddr = addr
}

// mmsghdr mirrors C struct mmsghdr. Using unix.Msghdr ensures
// correct field sizes and alignment on both 32-bit and 64-bit Linux.
// Go's natural struct padding produces the correct trailing padding.
type mmsghdr struct {
	Hdr    unix.Msghdr
	MsgLen uint32
}

type sockaddrInet4Raw struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

// Batch accumulates raw IPv4 packets and sends them via a single
// sendmmsg syscall, amortising kernel-transition overhead across
// batchSize packets.
//
// Loaded via purego (no CGO).  NewBatch returns nil when sendmmsg
// is not available.
type Batch struct {
	fd        socketFD
	count     int
	batchSize int
	maxPktLen int
	pkts      []byte // flat buffer: batchSize * maxPktLen
	pktLens   []int  // actual length of each queued packet
	addrs     []sockaddrInet4Raw
	iovs      []unix.Iovec
	msgs      []mmsghdr
}

// NewBatch creates a batch sender that accumulates up to batchSize
// packets of at most maxPktLen bytes each, sending them all in one
// sendmmsg syscall.  Returns nil if sendmmsg is not available.
func NewBatch(fd socketFD, batchSize, maxPktLen int) *Batch {
	if sendmmsgAddr == 0 {
		return nil
	}
	b := &Batch{
		fd:        fd,
		batchSize: batchSize,
		maxPktLen: maxPktLen,
		pkts:      make([]byte, batchSize*maxPktLen),
		pktLens:   make([]int, batchSize),
		addrs:     make([]sockaddrInet4Raw, batchSize),
		iovs:      make([]unix.Iovec, batchSize),
		msgs:      make([]mmsghdr, batchSize),
	}
	for i := 0; i < batchSize; i++ {
		b.addrs[i].Family = syscall.AF_INET
		b.iovs[i].Base = &b.pkts[i*maxPktLen]
		b.msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&b.addrs[i]))
		b.msgs[i].Hdr.Namelen = 16 // sizeof(sockaddr_in)
		b.msgs[i].Hdr.Iov = &b.iovs[i]
		b.msgs[i].Hdr.Iovlen = 1
	}
	return b
}

// Add copies pkt into the batch and sets the destination IPv4 address.
// When the batch is full, it is flushed automatically.
func (b *Batch) Add(pkt []byte, dstIP [4]byte) error {
	i := b.count
	off := i * b.maxPktLen
	n := copy(b.pkts[off:off+b.maxPktLen], pkt)
	b.pktLens[i] = n
	b.iovs[i].SetLen(n)
	b.addrs[i].Addr = dstIP
	b.count++
	if b.count == b.batchSize {
		return b.Flush()
	}
	return nil
}

// Flush sends all queued packets via sendmmsg. If the kernel performs
// a partial send (fewer messages than requested), Flush retries the
// remaining messages.
func (b *Batch) Flush() error {
	if b.count == 0 {
		return nil
	}
	n := b.count
	b.count = 0

	sent := 0
	for sent < n {
		r1, _, errno := purego.SyscallN(
			sendmmsgAddr,
			uintptr(b.fd),
			uintptr(unsafe.Pointer(&b.msgs[sent])),
			uintptr(n-sent),
			0,
		)
		runtime.KeepAlive(b)
		// sendmmsg returns -1 on error; errno is only meaningful then.
		if int(r1) < 0 {
			return syscall.Errno(errno)
		}
		cnt := int(r1)
		if cnt == 0 {
			return syscall.EAGAIN
		}
		sent += cnt
	}
	return nil
}

// Len returns the number of packets currently queued.
func (b *Batch) Len() int { return b.count }
