package probes

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/internal/discover/service/probes/echo"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/ftp"
	httpProbe "github.com/Method-Security/networkscan/internal/discover/service/probes/http"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/imap"
	kafka "github.com/Method-Security/networkscan/internal/discover/service/probes/kafka/kafkaNew"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/modbus"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/mqtt/mqtt3"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/mqtt/mqtt5"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/mysql"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/openvpn"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/pop3"
	postgres "github.com/Method-Security/networkscan/internal/discover/service/probes/postgresql"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/redis"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/rsync"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/smtp"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/stun"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/telnet"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/vnc"
)

func readRequest(c net.Conn) []byte { b := make([]byte, 4096); n, _ := c.Read(b); return b[:n] }
func reply(c net.Conn, b []byte)    { _, _ = c.Write(b) }

func TestNativeTCPProbesOnLoopback(t *testing.T) {
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificates := certServer.TLS.Certificates
	certServer.Close()
	imapServer := func(c net.Conn) {
		reply(c, []byte("* OK IMAP ready\r\n"))
		r := string(readRequest(c))
		tag := strings.Fields(r)
		if len(tag) > 0 {
			reply(c, []byte("* CAPABILITY IMAP4rev1\r\n"+tag[0]+" OK done\r\n"))
		}
	}
	popServer := func(c net.Conn) {
		reply(c, []byte("+OK POP3 ready\r\n"))
		readRequest(c)
		reply(c, []byte("-ERR unknown command\r\n"))
	}
	mqttServer := func(c net.Conn) {
		r := readRequest(c)
		if len(r) > 8 && r[8] == 5 {
			reply(c, []byte{0x20, 3, 0, 0, 0})
		} else {
			reply(c, []byte{0x20, 2, 0, 0})
		}
	}
	cases := []struct {
		name     string
		p        Fingerprinter
		protocol string
		secure   bool
		serve    func(net.Conn)
	}{
		{"echo", &echo.EchoPlugin{}, "ECHO", false, func(c net.Conn) { reply(c, readRequest(c)) }},
		{"ftp", &ftp.FTPPlugin{}, "FTP", false, func(c net.Conn) { reply(c, []byte("220 (vsFTPd 3.0.5)\r\n")) }},
		{"imap", &imap.IMAPPlugin{}, "IMAP", false, imapServer},
		{"imaps", &imap.TLSPlugin{}, "IMAPS", true, imapServer},
		{"pop3", &pop3.POP3Plugin{}, "POP3", false, popServer},
		{"pop3s", &pop3.TLSPlugin{}, "POP3S", true, popServer},
		{"mqtt3", &mqtt3.MQTT3Plugin{}, "MQTT3", false, mqttServer},
		{"mqtt3tls", &mqtt3.TLSPlugin{}, "MQTT3", true, mqttServer},
		{"mqtt5", &mqtt5.MQTT5Plugin{}, "MQTT5", false, mqttServer},
		{"mqtt5tls", &mqtt5.TLSPlugin{}, "MQTT5", true, mqttServer},
		{"vnc", &vnc.VNCPlugin{}, "VNC", false, func(c net.Conn) { reply(c, []byte("RFB 003.008\n")) }},
		{"telnet", &telnet.TELNETPlugin{}, "TELNET", false, func(c net.Conn) { reply(c, []byte{255, 251, 1}) }},
		{"rsync", &rsync.RSYNCPlugin{}, "RSYNC", false, func(c net.Conn) { readRequest(c); reply(c, []byte("@RSYNCD: 31.0\n")) }},
		{"postgresql", &postgres.POSTGRESPlugin{}, "POSTGRESQL", false, func(c net.Conn) { readRequest(c); reply(c, []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}) }},
		{"mysql", &mysql.MYSQLPlugin{}, "MYSQL", false, func(c net.Conn) {
			b := append([]byte{0, 0, 0, 0, 10}, []byte("8.0.28\x00")...)
			b = append(b, make([]byte, 40)...)
			b[0] = byte(len(b) - 4)
			reply(c, b)
		}},
		{"kafka", &kafka.Plugin{}, "KAFKA", false, func(c net.Conn) {
			r := readRequest(c)
			if len(r) < 12 {
				return
			}
			b := make([]byte, 14)
			binary.BigEndian.PutUint32(b, 10)
			copy(b[4:8], r[8:12])
			reply(c, b)
		}},
		{"kafkatls", &kafka.TLSPlugin{}, "KAFKA", true, func(c net.Conn) {
			r := readRequest(c)
			if len(r) < 12 {
				return
			}
			b := make([]byte, 14)
			binary.BigEndian.PutUint32(b, 10)
			copy(b[4:8], r[8:12])
			reply(c, b)
		}},
		{"modbus", &modbus.MODBUSPlugin{}, "MODBUS", false, func(c net.Conn) {
			r := readRequest(c)
			if len(r) < 2 {
				return
			}
			b := []byte{r[0], r[1], 0, 0, 0, 4, 1, 2, 1, 0}
			reply(c, b)
		}},
		{"redistls", &redis.REDISTLSPlugin{}, "REDIS", true, func(c net.Conn) { readRequest(c); reply(c, []byte("-NOAUTH Authentication required.\r\n")) }},
		{"smtps", &smtp.TLSPlugin{}, "SMTPS", true, func(c net.Conn) {
			reply(c, []byte("220 test ESMTP ready\r\n"))
			readRequest(c)
			reply(c, []byte("250 test\r\n"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = l.Close() }()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := l.Accept()
				if err != nil {
					return
				}
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				if tc.secure {
					c = tls.Server(c, &tls.Config{Certificates: certificates})
				}
				tc.serve(c)
			}()
			port := l.Addr().(*net.TCPAddr).Port
			result, err := tc.p.Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "service.test", 2)
			if err != nil || result == nil {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			if string(result.Protocol) != tc.protocol || result.Host != "service.test" || result.Ip != "127.0.0.1" || result.Port != port || result.Tls == nil || *result.Tls != tc.secure {
				t.Fatalf("incorrect result: %#v", result)
			}
			if _, err := json.Marshal(result); err != nil {
				t.Fatal(err)
			}
			<-done
		})
	}
}

func TestHTTPHostSNIAndRedirect(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprint(secure), func(t *testing.T) {
			seen := make(chan *http.Request, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r
				w.Header().Set("Location", "http://127.0.0.1:1/elsewhere")
				w.WriteHeader(302)
			}))
			var p Fingerprinter = &httpProbe.HTTPPlugin{}
			if secure {
				server.StartTLS()
				p = &httpProbe.HTTPSPlugin{}
			} else {
				server.Start()
			}
			defer server.Close()
			result, err := p.Detect(context.Background(), net.ParseIP("127.0.0.1"), server.Listener.Addr().(*net.TCPAddr).Port, "service.test", 2)
			if err != nil || result == nil {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			req := <-seen
			if req.Host != "service.test" {
				t.Fatalf("Host=%s", req.Host)
			}
			if secure && (req.TLS == nil || req.TLS.ServerName != "service.test") {
				t.Fatalf("SNI=%#v", req.TLS)
			}
		})
	}
}

func TestNativeUDPProbes(t *testing.T) {
	cases := []struct {
		p        Fingerprinter
		protocol string
		response func([]byte) []byte
	}{
		{&stun.Plugin{}, "STUN", func(r []byte) []byte {
			b := append([]byte(nil), r[:20]...)
			b[0] = 1
			b[1] = 1
			b[2] = 0
			b[3] = 0
			return b
		}},
		{&openvpn.Plugin{}, "OPENVPN", func(r []byte) []byte {
			b := make([]byte, 26)
			b[0] = 8 << 3
			b[9] = 1
			copy(b[14:22], r[1:9])
			return b
		}},
	}
	for _, tc := range cases {
		t.Run(tc.protocol, func(t *testing.T) {
			c, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			go func() {
				b := make([]byte, 2048)
				n, a, e := c.ReadFrom(b)
				if e == nil {
					_, _ = c.WriteTo(tc.response(b[:n]), a)
				}
			}()
			result, err := tc.p.Detect(context.Background(), net.ParseIP("127.0.0.1"), c.LocalAddr().(*net.UDPAddr).Port, "udp.test", 2)
			if err != nil || result == nil || string(result.Protocol) != tc.protocol || result.Host != "udp.test" || result.Transport != "UDP" {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}

func TestEveryTCPProbeHonorsCancellation(t *testing.T) {
	for _, p := range TCP() {
		t.Run(fmt.Sprintf("%T", p), func(t *testing.T) {
			t.Parallel()
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = l.Close() }()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := l.Accept()
				if err != nil {
					return
				}
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				_, _ = io.Copy(io.Discard, bufio.NewReader(c))
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			result, _ := p.Detect(ctx, net.ParseIP("127.0.0.1"), l.Addr().(*net.TCPAddr).Port, "timeout.test", -1)
			if result != nil {
				t.Fatalf("silent server detected: %#v", result)
			}
			if time.Since(start) > 750*time.Millisecond {
				t.Fatal("plugin did not honor parent cancellation")
			}
			_ = l.Close()
			<-done
		})
	}
}

type replyConn struct{ *bytes.Reader }

func (c replyConn) Write(b []byte) (int, error) { return len(b), nil }
func (c replyConn) Close() error                { return nil }
func (c replyConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10000}
}
func (c replyConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1} }
func (c replyConn) SetDeadline(time.Time) error      { return nil }
func (c replyConn) SetReadDeadline(time.Time) error  { return nil }
func (c replyConn) SetWriteDeadline(time.Time) error { return nil }

func TestMalformedResponsesDoNotPanicOrMatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	target := probe.Target{Address: netip.MustParseAddrPort("127.0.0.1:1"), Host: "localhost", Context: ctx}
	for _, p := range TCP() {
		t.Run(fmt.Sprintf("%T", p), func(t *testing.T) {
			runner := p.(interface {
				Run(net.Conn, time.Duration, probe.Target) (*probe.Service, error)
			})
			for _, b := range [][]byte{nil, {0}, {0x20}, {0xff}, make([]byte, 7), make([]byte, 32), bytes.Repeat([]byte{0xff}, 32), []byte("HTTP/1.1 garbage\r\n\r\n")} {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("packet %x panicked: %v", b, r)
						}
					}()
					result, _ := runner.Run(replyConn{bytes.NewReader(b)}, time.Millisecond, target)
					if result != nil {
						t.Errorf("packet %x falsely matched %s", b, result.Protocol)
					}
				}()
			}
		})
	}
}
