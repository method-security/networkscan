package utils

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

func dialErr(inner error) error {
	return &net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 21},
		Err:  inner,
	}
}

func TestClassifyNetError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		category NetErrorCategory
		wantAddr string
	}{
		{name: "connection refused", err: dialErr(os.NewSyscallError("connect", syscall.ECONNREFUSED)), category: NetErrorConnRefused, wantAddr: "1.2.3.4:21"},
		{name: "connection reset", err: dialErr(os.NewSyscallError("read", syscall.ECONNRESET)), category: NetErrorConnReset},
		{name: "no route to host", err: dialErr(os.NewSyscallError("connect", syscall.EHOSTUNREACH)), category: NetErrorNoRouteToHost},
		{name: "network unreachable", err: dialErr(os.NewSyscallError("connect", syscall.ENETUNREACH)), category: NetErrorNetworkDown},
		{name: "syscall timeout", err: dialErr(os.NewSyscallError("connect", syscall.ETIMEDOUT)), category: NetErrorTimeout},
		{name: "dns not found", err: &net.DNSError{Name: "nope.example.com", IsNotFound: true}, category: NetErrorDNS, wantAddr: "nope.example.com"},
		{name: "context deadline", err: context.DeadlineExceeded, category: NetErrorTimeout},
		{name: "context canceled", err: context.Canceled, category: NetErrorCanceled},
		{name: "tls unknown authority", err: x509.UnknownAuthorityError{}, category: NetErrorTLS},
		{name: "tls string", err: errors.New("tls: handshake failure"), category: NetErrorTLS},
		{name: "unknown", err: errors.New("weird failure"), category: NetErrorOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detail := ClassifyNetError(tt.err)
			if detail.Category != tt.category {
				t.Fatalf("category = %q, want %q (cause=%q)", detail.Category, tt.category, detail.Cause)
			}
			if detail.Cause == "" {
				t.Fatalf("cause must never be empty for %v", tt.err)
			}
			if tt.wantAddr != "" && detail.Address != tt.wantAddr {
				t.Fatalf("address = %q, want %q", detail.Address, tt.wantAddr)
			}
			if detail.String() == "" {
				t.Fatalf("String() must not be empty")
			}
		})
	}
}

func TestClassifyNetErrorNil(t *testing.T) {
	if got := ClassifyNetError(nil); got.Category != "" || got.Cause != "" {
		t.Fatalf("nil error should classify to empty detail, got %+v", got)
	}
}
