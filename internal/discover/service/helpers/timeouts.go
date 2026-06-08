package helpers

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

func Timeout(timeout int) time.Duration {
	if timeout < 0 {
		return 0
	}
	return time.Duration(timeout) * time.Second
}

func HasTimeout(timeout int) bool {
	return timeout >= 0
}

func Context(ctx context.Context, timeout int) (context.Context, context.CancelFunc) {
	if !HasTimeout(timeout) {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, Timeout(timeout))
}

func ContextDuration(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func After(timeout int) <-chan time.Time {
	if !HasTimeout(timeout) {
		return nil
	}
	return time.After(Timeout(timeout))
}

func TCPConn(ctx context.Context, ip net.IP, port int, timeout int) (net.Conn, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	return Dial(ctx, "tcp", addr, timeout)
}

func UDPConn(ctx context.Context, ip net.IP, port int, timeout int) (net.Conn, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	return Dial(ctx, "udp", addr, timeout)
}

func Dial(ctx context.Context, network, address string, timeout int) (net.Conn, error) {
	dialer := net.Dialer{}
	if HasTimeout(timeout) {
		dialer.Timeout = Timeout(timeout)
	}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if err := SetDeadline(conn, timeout); err != nil {
		_ = conn.Close()
		return nil, err
	}
	stopCancelWatch := CloseConnOnCancel(ctx, conn)
	return &cancelAwareConn{Conn: conn, stopCancelWatch: stopCancelWatch}, nil
}

func DialDuration(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{}
	if timeout > 0 {
		dialer.Timeout = timeout
	}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if err := SetDeadlineDuration(conn, timeout); err != nil {
		_ = conn.Close()
		return nil, err
	}
	stopCancelWatch := CloseConnOnCancel(ctx, conn)
	return &cancelAwareConn{Conn: conn, stopCancelWatch: stopCancelWatch}, nil
}

func SetDeadline(conn net.Conn, timeout int) error {
	if !HasTimeout(timeout) {
		return nil
	}
	return conn.SetDeadline(time.Now().Add(Timeout(timeout)))
}

func SetReadDeadline(conn net.Conn, timeout int) error {
	if !HasTimeout(timeout) {
		return nil
	}
	return conn.SetReadDeadline(time.Now().Add(Timeout(timeout)))
}

func SetWriteDeadline(conn net.Conn, timeout int) error {
	if !HasTimeout(timeout) {
		return nil
	}
	return conn.SetWriteDeadline(time.Now().Add(Timeout(timeout)))
}

func SetDeadlineDuration(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	return conn.SetDeadline(time.Now().Add(timeout))
}

func SetReadDeadlineDuration(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	return conn.SetReadDeadline(time.Now().Add(timeout))
}

func SetWriteDeadlineDuration(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	return conn.SetWriteDeadline(time.Now().Add(timeout))
}

func CloseConnOnCancel(ctx context.Context, conn net.Conn) func() {
	return closeConnOnCancel(ctx, conn)
}

func TCPExchange(ctx context.Context, ip net.IP, port int, timeout int, probe []byte, maxRead int) ([]byte, error) {
	conn, err := TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(probe); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	buf := make([]byte, maxRead)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return buf[:n], nil
}

func TCPReadBanner(ctx context.Context, ip net.IP, port int, timeout int, maxRead int) ([]byte, error) {
	conn, err := TCPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	buf := make([]byte, maxRead)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return buf[:n], nil
}

func UDPExchange(ctx context.Context, ip net.IP, port int, timeout int, probe []byte, maxRead int) ([]byte, error) {
	conn, err := UDPConn(ctx, ip, port, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(probe); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	buf := make([]byte, maxRead)
	n, err := conn.Read(buf)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return buf[:n], nil
}

func closeConnOnCancel(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

type cancelAwareConn struct {
	net.Conn
	once            sync.Once
	stopCancelWatch func()
}

func (c *cancelAwareConn) Close() error {
	c.once.Do(c.stopCancelWatch)
	return c.Conn.Close()
}
