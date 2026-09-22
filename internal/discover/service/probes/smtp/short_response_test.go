package smtp

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
)

func TestShortSMTPReplies(t *testing.T) {
	for _, input := range [][]byte{nil, []byte("2"), []byte("22")} {
		if ok, _ := handleSMTPConn(input); ok {
			t.Fatalf("accepted banner %q", input)
		}
		if ok, _ := handleSMTPHelo(input); ok {
			t.Fatalf("accepted EHLO %q", input)
		}
	}
	if ok, _ := handleSMTPConn([]byte("220 ready\r\n")); !ok {
		t.Fatal("rejected valid banner")
	}
	if ok, _ := handleSMTPHelo([]byte("250 ready\r\n")); !ok {
		t.Fatal("rejected valid EHLO")
	}
	for _, secure := range []bool{false, true} {
		for _, ehlo := range []bool{false, true} {
			for _, short := range []string{"2", "22"} {
				t.Run(fmt.Sprintf("tls=%v/ehlo=%v/%s", secure, ehlo, short), func(t *testing.T) {
					client, server := net.Pipe()
					defer func() { _ = client.Close() }()
					done := make(chan struct{})
					go func() {
						defer close(done)
						defer func() { _ = server.Close() }()
						_ = server.SetDeadline(time.Now().Add(2 * time.Second))
						if ehlo {
							_, _ = server.Write([]byte("220 ready\r\n"))
							_, _ = server.Read(make([]byte, 256))
						}
						_, _ = server.Write([]byte(short))
					}()
					var result *probe.Service
					if secure {
						result, _ = (&TLSPlugin{}).Run(client, time.Second, probe.Target{})
					} else {
						result, _ = (&SMTPPlugin{}).Run(client, time.Second, probe.Target{})
					}
					if result != nil {
						t.Fatalf("accepted short reply: %+v", result)
					}
					<-done
				})
			}
		}
	}
}
