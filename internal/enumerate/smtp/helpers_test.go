package smtp

import (
	"bufio"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/utils"
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

// RFC 5321 permits 421 and 554 greetings, so every one of these must read as plaintext SMTP.
func TestTryTCPConnectionAcceptsAllReplyCodeGreetings(t *testing.T) {
	greetings := []string{
		"220 mail.example.com ESMTP ready\r\n",
		"421 mail.example.com Service not available\r\n",
		"554 no SMTP service here\r\n",
	}

	for _, greeting := range greetings {
		ln := listenerWriting(t, greeting)

		conn, err := tryTCPConnection(context.Background(), ln.Addr().String())
		if err != nil {
			_ = ln.Close()
			t.Errorf("tryTCPConnection with greeting %q: %v", greeting, err)
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, readErr := bufio.NewReader(conn).ReadString('\n')
		if readErr != nil {
			t.Errorf("ReadString for %q: %v", greeting, readErr)
		} else if line != greeting {
			t.Errorf("greeting = %q, want %q — peeked bytes were lost", line, greeting)
		}
		_ = conn.Close()
		_ = ln.Close()
	}
}

func TestTryTCPConnectionRejectsTLSHandshake(t *testing.T) {
	ln := listenerWriting(t, "\x16\x03\x01\x00\x9f")
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

// An smtps:// scheme must go straight to TLS rather than spending the greeting peek.
func TestSmtpsSchemeSkipsGreetingProbe(t *testing.T) {
	ln := listenerWriting(t, "")
	defer func() { _ = ln.Close() }()

	lib := &LibraryEnumerateSMTP{}
	// EnumerateTarget takes its deadline from the caller; the engine wraps every call in one.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, errs := lib.EnumerateTarget(ctx, "smtps://"+ln.Addr().String())
	elapsed := time.Since(start)

	if len(errs) == 0 {
		t.Error("want an error: the listener is silent and cannot complete a TLS handshake")
	}
	if elapsed >= implicitTLSPeekTimeout {
		t.Errorf("took %v; the greeting peek should have been skipped entirely", elapsed)
	}
}

func TestSplitTargetSchemeRoundTrip(t *testing.T) {
	cases := map[string][2]string{
		"smtps://h:465": {"smtps", "h:465"},
		"smtp://h:25":   {"smtp", "h:25"},
		"h:25":          {"", "h:25"},
		"SMTPS://h:465": {"smtps", "h:465"},
	}
	for in, want := range cases {
		scheme, rest := utils.SplitTargetScheme(in)
		if scheme != want[0] || rest != want[1] {
			t.Errorf("SplitTargetScheme(%q) = (%q, %q), want (%q, %q)", in, scheme, rest, want[0], want[1])
		}
	}
}
