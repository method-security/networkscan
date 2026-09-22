package wireio

import (
	"errors"
	"net"
	"testing"
	"time"
)

type failingConn struct {
	net.Conn
	deadlineError error
	ioError       error
}

func (c failingConn) SetReadDeadline(time.Time) error  { return c.deadlineError }
func (c failingConn) SetWriteDeadline(time.Time) error { return c.deadlineError }
func (c failingConn) Read([]byte) (int, error)         { return 0, c.ioError }
func (c failingConn) Write([]byte) (int, error)        { return 0, c.ioError }

func TestIOErrorsPreserveCause(t *testing.T) {
	cause := errors.New("test connection failure")
	for _, tc := range []struct {
		name string
		conn failingConn
		send bool
	}{
		{name: "write deadline", conn: failingConn{deadlineError: cause}, send: true},
		{name: "read deadline", conn: failingConn{deadlineError: cause}},
		{name: "write", conn: failingConn{ioError: cause}, send: true},
		{name: "read", conn: failingConn{ioError: cause}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.send {
				err = Send(tc.conn, []byte("test"), time.Second)
			} else {
				_, err = Recv(tc.conn, time.Second)
			}
			if !errors.Is(err, cause) {
				t.Fatalf("expected wrapped connection failure, got %v", err)
			}
		})
	}
}

func TestSendRejectsShortWrite(t *testing.T) {
	if err := Send(failingConn{}, []byte("test"), time.Second); err == nil {
		t.Fatal("expected error for incomplete write")
	}
}
