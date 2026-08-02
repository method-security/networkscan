// Package rawsend provides high-performance raw IPv4 packet sending
// primitives that bypass Go's net.IPConn overhead.
//
// Sender wraps a raw socket file descriptor and calls sendto() directly
// via the syscall package, eliminating net.IPConn.WriteTo's mutex,
// poll.FD, and error-wrapping overhead (~1µs per packet).
//
// On Linux, NewBatch returns a Batch that accumulates packets and
// sends them via sendmmsg (loaded through purego, no CGO required),
// amortising syscall overhead across N packets.
package rawsend

import (
	"net"
	"syscall"
)

// socketFD is the platform-specific file descriptor / handle type.
// Unix: int, Windows: syscall.Handle (uintptr).
type socketFD = sysSocketFD

// Sender sends raw IPv4 packets via direct sendto() syscall,
// bypassing Go's net.IPConn.WriteTo overhead (poll.FD mutex,
// deadline management, error wrapping).
type Sender struct {
	fd   socketFD
	conn *net.IPConn           // prevent GC from closing fd
	sa   syscall.SockaddrInet4 // reused per send; only Addr changes
}

// NewFromIPConn creates a Sender by extracting the raw file descriptor
// from conn.  The conn reference is retained to prevent garbage
// collection (which would close the fd).
func NewFromIPConn(conn *net.IPConn) (*Sender, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var fd socketFD
	var controlErr error
	controlErr = rc.Control(func(fdPtr uintptr) { fd = socketFD(fdPtr) })
	if controlErr != nil {
		return nil, controlErr
	}
	return &Sender{fd: fd, conn: conn}, nil
}

// NewFromFD creates a Sender from an already-known file descriptor.
// conn must be the net.IPConn that owns fd (kept alive to prevent GC).
func NewFromFD(fd socketFD, conn *net.IPConn) *Sender {
	return &Sender{fd: fd, conn: conn}
}

// FD returns the raw socket file descriptor (or handle on Windows).
func (s *Sender) FD() socketFD { return s.fd }

// SendTo transmits pkt to the IPv4 address dstIP using a direct
// sendto() syscall.  The kernel adds the IPv4 header based on the
// socket's protocol (e.g. IPPROTO_TCP).
//
// SendTo is NOT safe for concurrent use from multiple goroutines
// because it reuses an internal sockaddr struct without locking.
func (s *Sender) SendTo(pkt []byte, dstIP [4]byte) error {
	s.sa.Addr = dstIP
	return syscall.Sendto(s.fd, pkt, 0, &s.sa)
}
