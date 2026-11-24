package plugins

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestDetectKerberosRejectsPartialResponse(t *testing.T) {
	response := []byte{
		0x00, 0x00, 0x00, 0x04, // declared response length
		0x7e, // KRB_ERROR tag followed by a truncated payload
	}
	conn := &kerberosTestConn{reader: bytes.NewReader(response)}

	detected, tlsUsed, err := detectKerberos(conn, "EXAMPLE.COM", time.Second, false)

	if detected {
		t.Fatal("expected a partial Kerberos response to be rejected")
	}
	if tlsUsed {
		t.Fatal("expected plaintext mode")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}

type kerberosTestConn struct {
	reader *bytes.Reader
}

func (c *kerberosTestConn) Read(p []byte) (int, error)     { return c.reader.Read(p) }
func (*kerberosTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*kerberosTestConn) Close() error                     { return nil }
func (*kerberosTestConn) LocalAddr() net.Addr              { return kerberosTestAddr("local") }
func (*kerberosTestConn) RemoteAddr() net.Addr             { return kerberosTestAddr("remote") }
func (*kerberosTestConn) SetDeadline(time.Time) error      { return nil }
func (*kerberosTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*kerberosTestConn) SetWriteDeadline(time.Time) error { return nil }

type kerberosTestAddr string

func (a kerberosTestAddr) Network() string { return string(a) }
func (a kerberosTestAddr) String() string  { return string(a) }
