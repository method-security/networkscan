package plugins

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

func serviceTimeout(timeout int) time.Duration {
	return helpers.Timeout(timeout)
}

func serviceHasTimeout(timeout int) bool {
	return helpers.HasTimeout(timeout)
}

func serviceContext(ctx context.Context, timeout int) (context.Context, context.CancelFunc) {
	return helpers.Context(ctx, timeout)
}

func serviceContextDuration(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func serviceAfter(timeout int) <-chan time.Time {
	if !serviceHasTimeout(timeout) {
		return nil
	}
	return time.After(serviceTimeout(timeout))
}

func setServiceDeadline(conn net.Conn, timeout int) error {
	return helpers.SetDeadline(conn, timeout)
}

func setServiceReadDeadline(conn net.Conn, timeout int) error {
	return helpers.SetReadDeadline(conn, timeout)
}

func setServiceWriteDeadline(conn net.Conn, timeout int) error {
	return helpers.SetWriteDeadline(conn, timeout)
}

func setServiceDeadlineDuration(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	return conn.SetDeadline(time.Now().Add(timeout))
}

func setServiceReadDeadlineDuration(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	return conn.SetReadDeadline(time.Now().Add(timeout))
}

func setServiceWriteDeadlineDuration(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	return conn.SetWriteDeadline(time.Now().Add(timeout))
}

func dialService(ctx context.Context, network, address string, timeout int) (net.Conn, error) {
	dialer := net.Dialer{}
	if serviceHasTimeout(timeout) {
		dialer.Timeout = serviceTimeout(timeout)
	}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if err := setServiceDeadline(conn, timeout); err != nil {
		_ = conn.Close()
		return nil, err
	}
	stopCancelWatch := helpers.CloseConnOnCancel(ctx, conn)
	return &cancelAwareConn{Conn: conn, stopCancelWatch: stopCancelWatch}, nil
}

func dialServiceDuration(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{}
	if timeout > 0 {
		dialer.Timeout = timeout
	}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if err := setServiceDeadlineDuration(conn, timeout); err != nil {
		_ = conn.Close()
		return nil, err
	}
	stopCancelWatch := helpers.CloseConnOnCancel(ctx, conn)
	return &cancelAwareConn{Conn: conn, stopCancelWatch: stopCancelWatch}, nil
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
