package netdial

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/internal/config"
)

func TestDialContextDirectTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			accepted <- acceptErr
			return
		}
		_ = conn.Close()
		accepted <- nil
	}()

	conn, err := DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()

	if err := <-accepted; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("accept: %v", err)
	}
}

func TestDialContextRejectsUnsupportedSocksScheme(t *testing.T) {
	ctx := config.SetProxyConfig(context.Background(), "http://127.0.0.1:8080")
	_, err := DialContext(ctx, "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported SOCKS proxy scheme") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDialContextSocksHonorsTimeoutOption(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	serverDone := make(chan struct{})
	defer close(serverDone)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		<-serverDone
	}()

	ctx := config.SetProxyConfig(context.Background(), "socks5://"+ln.Addr().String())
	result := make(chan error, 1)
	start := time.Now()
	go func() {
		conn, dialErr := DialContext(ctx, "tcp", "example.com:443", WithTimeout(75*time.Millisecond))
		if conn != nil {
			_ = conn.Close()
		}
		result <- dialErr
	}()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected timeout error")
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("SOCKS dial ignored timeout option; elapsed %s", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SOCKS dial did not return after timeout option")
	}
}
