package plugins

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
)

func TestMongoDBWarningFallbackReservesAttemptBudget(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections sync.WaitGroup
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				reader := bufio.NewReader(conn)
				prefix, err := reader.Peek(4)
				if err != nil {
					return
				}
				// Both the native driver and TLS warning probe deliberately stall.
				if string(prefix) != "GET " {
					_, _ = io.Copy(io.Discard, reader)
					return
				}
				request, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				_ = request.Body.Close()
				body := "It looks like you are trying to access MongoDB over HTTP on the native driver port.\r\n"
				_, _ = fmt.Fprintf(conn, "HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-stopped
		connections.Wait()
	})

	for _, inheritedDeadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("inherited-deadline=%t", inheritedDeadline), func(t *testing.T) {
			ctx := context.Background()
			timeout := 1
			if inheritedDeadline {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Second)
				defer cancel()
				timeout = 10
			}
			start := time.Now()
			result, err := (MongoDBFingerprinter{}).Detect(ctx, net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, listener.Addr()), "127.0.0.1", timeout)
			if err != nil || result == nil || result.Protocol != common.ProtocolTypeMongodb || result.Tls == nil || *result.Tls {
				t.Fatalf("missing plaintext warning fallback: %+v, %v", result, err)
			}
			if elapsed := time.Since(start); elapsed >= time.Second {
				t.Fatalf("fallback exceeded overall deadline: %s", elapsed)
			}
		})
	}
}

func TestMongoDBWarningFallbackTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "It looks like you are trying to access MongoDB over HTTP on the native driver port.\r\n")
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := (MongoDBFingerprinter{}).Detect(ctx, net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, server.Listener.Addr()), "mongo.invalid", 2)
	if err != nil || result == nil || result.Protocol != common.ProtocolTypeMongodb || result.Tls == nil || !*result.Tls {
		t.Fatalf("missing TLS warning fallback: %+v, %v", result, err)
	}
}

func TestMongoDBWarningFallbackRejectsGenericHTTP(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := (MongoDBFingerprinter{}).Detect(ctx, net.ParseIP("127.0.0.1"), nativeHTTPProductPort(t, server.Listener.Addr()), "127.0.0.1", 1)
	if err != nil || result != nil {
		t.Fatalf("generic HTTP classified as MongoDB: %+v, %v", result, err)
	}
}
