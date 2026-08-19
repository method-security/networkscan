package smtp

import (
	"bufio"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func listenerWriting(t *testing.T, payload string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		if payload != "" {
			_, _ = conn.Write([]byte(payload))
		}
		time.Sleep(3 * time.Second)
		_ = conn.Close()
	}()
	return ln
}

func TestTryTCPConnectionPreservesGreeting(t *testing.T) {
	const greeting = "220 mail.example.com ESMTP ready\r\n"
	ln := listenerWriting(t, greeting)
	defer func() { _ = ln.Close() }()

	conn, err := tryTCPConnection(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("tryTCPConnection: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if line != greeting {
		t.Errorf("greeting = %q, want %q — peeked bytes were lost", line, greeting)
	}
}

func TestTryTCPConnectionRejectsNonGreeting(t *testing.T) {
	ln := listenerWriting(t, "\x16\x03\x01 not smtp\r\n")
	defer func() { _ = ln.Close() }()

	conn, err := tryTCPConnection(context.Background(), ln.Addr().String())
	if !errors.Is(err, errImplicitTLSSuspected) {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("err = %v, want errImplicitTLSSuspected", err)
	}
}

// A silent listener off :465 is a tarpit, not implicit TLS, so the connection must survive the peek.
func TestTryTCPConnectionKeepsSilentNonSmtpsPort(t *testing.T) {
	ln := listenerWriting(t, "")
	defer func() { _ = ln.Close() }()

	conn, err := tryTCPConnection(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("tryTCPConnection on silent non-465 port: %v, want nil", err)
	}
	_ = conn.Close()
}

func TestPortFromTarget(t *testing.T) {
	cases := map[string]int{
		"10.0.0.1:465":      465,
		"10.0.0.1:25":       25,
		"[::1]:465":         465,
		"10.0.0.1":          0,
		"10.0.0.1:notaport": 0,
	}
	for target, want := range cases {
		if got := portFromTarget(target); got != want {
			t.Errorf("portFromTarget(%q) = %d, want %d", target, got, want)
		}
	}
}
