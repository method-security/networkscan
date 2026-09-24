package plugins

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/asn1"
	"encoding/binary"
	"io"
	"net"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
)

type nativeTCPDiscoveryProbe interface {
	Name() string
	DefaultPorts() []int
	Detect(context.Context, net.IP, int, string, int) (*discover.ServiceDetails, error)
}

func nativeTCPDiscoveryListener(t *testing.T, serve func(net.Conn)) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		serve(conn)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("fixture did not stop")
		}
	})
	return listener.Addr().(*net.TCPAddr).Port
}

func nativeTCPDiscoveryTLS(t *testing.T) *tls.Config {
	t.Helper()
	server := httptest.NewTLSServer(nil)
	config := server.TLS.Clone()
	server.Close()
	return config
}

func nativeTCPDiscoveryExpect(t *testing.T, conn net.Conn, expected string) {
	t.Helper()
	b := make([]byte, len(expected))
	if _, err := io.ReadFull(conn, b); err != nil {
		t.Errorf("read request: %v", err)
		return
	}
	if string(b) != expected {
		t.Errorf("request = %q, want %q", b, expected)
	}
}

func nativeTCPDiscoverySend(t *testing.T, conn net.Conn, response string) {
	t.Helper()
	// Deliberate fragmentation exercises stream framing, independent of packets.
	for start := 0; start < len(response); start += 3 {
		end := start + 3
		if end > len(response) {
			end = len(response)
		}
		if _, err := io.WriteString(conn, response[start:end]); err != nil {
			t.Errorf("send response: %v", err)
			return
		}
	}
}

func TestNativeTCPDiscoveryInventory(t *testing.T) {
	tests := []struct {
		probe nativeTCPDiscoveryProbe
		name  string
		port  int
	}{
		{RDPFingerprinter{}, "rdp", 3389}, {RDPTLSFingerprinter{}, "rdp", 3389},
		{VNCFingerprinter{}, "VNC", 5900}, {TelnetFingerprinter{}, "telnet", 23},
		{EchoFingerprinter{}, "echo", 7}, {FTPFingerprinter{}, "ftp", 21},
		{SNPPFingerprinter{}, "snpp", 444}, {RsyncFingerprinter{}, "rsync", 873},
		{RTSPFingerprinter{}, "rtsp", 554}, {IMAPFingerprinter{}, "imap", 143},
		{IMAPTLSFingerprinter{}, "imaps", 993}, {POP3Fingerprinter{}, "pop3", 110},
		{POP3TLSFingerprinter{}, "pop3s", 995}, {SMTPTLSFingerprinter{}, "smtps", 465},
	}
	for _, test := range tests {
		if test.probe.Name() != test.name || !reflect.DeepEqual(test.probe.DefaultPorts(), []int{test.port}) {
			t.Errorf("%T inventory mismatch", test.probe)
		}
	}
}

func TestNativeTCPDiscoveryPositive(t *testing.T) {
	tlsConfig := nativeTCPDiscoveryTLS(t)
	tests := []struct {
		name       string
		probe      nativeTCPDiscoveryProbe
		secure     bool
		protocol   common.ProtocolType
		key, value string
		serve      func(*testing.T, net.Conn)
	}{
		{"vnc-banner-only", VNCFingerprinter{}, false, common.ProtocolTypeVnc, "banner", "RFB 003.008", func(t *testing.T, c net.Conn) { nativeTCPDiscoverySend(t, c, "RFB 003.008\n") }},
		{"telnet", TelnetFingerprinter{}, false, common.ProtocolTypeTelnet, "serverData", "Welcome", func(t *testing.T, c net.Conn) {
			nativeTCPDiscoveryExpect(t, c, string([]byte{255, 253, 3}))
			nativeTCPDiscoverySend(t, c, "Welcome\r\n"+string([]byte{255, 251, 3}))
		}},
		{"echo", EchoFingerprinter{}, false, common.ProtocolTypeEcho, "application_protocol", "ECHO", func(t *testing.T, c net.Conn) {
			line, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				t.Error(err)
				return
			}
			nativeTCPDiscoverySend(t, c, line)
		}},
		{"ftp", FTPFingerprinter{}, false, common.ProtocolTypeFtp, "system", "UNIX Type: L8", func(t *testing.T, c net.Conn) {
			nativeTCPDiscoverySend(t, c, "220-FTP test\r\nReady soon\r\n220 Ready\r\n")
			nativeTCPDiscoveryExpect(t, c, "SYST\r\n")
			nativeTCPDiscoverySend(t, c, "215 UNIX Type: L8\r\n")
			nativeTCPDiscoveryExpect(t, c, "FEAT\r\n")
			nativeTCPDiscoverySend(t, c, "211-Features\r\n UTF8\r\n211 End\r\n")
		}},
		{"snpp", SNPPFingerprinter{}, false, common.ProtocolTypeSnpp, "banner", "220 Paging service", func(t *testing.T, c net.Conn) {
			nativeTCPDiscoverySend(t, c, "220 Paging service\r\n")
			nativeTCPDiscoveryExpect(t, c, "HELP\r\n")
			nativeTCPDiscoverySend(t, c, "214 PAGE pager\r\n214 MESS message\r\n214 SEND\r\n250 End\r\n")
		}},
		{"rsync", RsyncFingerprinter{}, false, common.ProtocolTypeRsync, "modules", "archive\tPublic archive", func(t *testing.T, c net.Conn) {
			nativeTCPDiscoverySend(t, c, "@RSYNCD: 31.0 sha512 sha256\n")
			nativeTCPDiscoveryExpect(t, c, "@RSYNCD: 31.0\n#list\n")
			nativeTCPDiscoverySend(t, c, "archive\tPublic archive\n@RSYNCD: EXIT\n")
		}},
		{"rtsp-auth-required", RTSPFingerprinter{}, false, common.ProtocolTypeRtsp, "serverInfo", "Camera/2.1", func(t *testing.T, c net.Conn) {
			nativeTCPDiscoveryExpect(t, c, "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: networkscan\r\n\r\n")
			nativeTCPDiscoverySend(t, c, "RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nServer: Camera/2.1\r\nWWW-Authenticate: Basic realm=local\r\n\r\n")
		}},
		{"imap", IMAPFingerprinter{}, false, common.ProtocolTypeImap, "capabilities", "IMAP4rev1 STARTTLS AUTH=PLAIN", nativeTCPDiscoveryIMAP},
		{"imaps", IMAPTLSFingerprinter{}, true, common.ProtocolTypeImaps, "capabilities", "IMAP4rev1 STARTTLS AUTH=PLAIN", nativeTCPDiscoveryIMAP},
		{"pop3", POP3Fingerprinter{}, false, common.ProtocolTypePop3, "implementation", "LocalMail 2", nativeTCPDiscoveryPOP3},
		{"pop3s", POP3TLSFingerprinter{}, true, common.ProtocolTypePop3S, "apopTimestamp", "<123@local>", nativeTCPDiscoveryPOP3},
		{"smtps", SMTPTLSFingerprinter{}, true, common.ProtocolTypeSmtps, "authMethods", "[PLAIN LOGIN]", func(t *testing.T, c net.Conn) {
			nativeTCPDiscoverySend(t, c, "220 local ESMTP TestMail 1.2\r\n")
			nativeTCPDiscoveryExpect(t, c, "EHLO scanner.local\r\n")
			nativeTCPDiscoverySend(t, c, "250-local\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 1024\r\n")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			port := nativeTCPDiscoveryListener(t, func(c net.Conn) {
				if test.secure {
					secured := tls.Server(c, tlsConfig)
					if err := secured.Handshake(); err != nil {
						t.Error(err)
						return
					}
					c = secured
				}
				test.serve(t, c)
			})
			result, err := test.probe.Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || result.Protocol != test.protocol || result.Transport != common.TransportTypeTcp {
				t.Fatalf("bad result: %#v", result)
			}
			if test.secure && (result.Tls == nil || !*result.Tls) {
				t.Fatal("missing TLS signal")
			}
			if got := result.Metadata.Generic.Metadata[test.key]; got != test.value {
				t.Errorf("metadata[%s]=%q, want %q", test.key, got, test.value)
			}
		})
	}
}

func nativeTCPDiscoveryIMAP(t *testing.T, c net.Conn) {
	nativeTCPDiscoverySend(t, c, "* OK Local IMAP ready\r\n")
	nativeTCPDiscoveryExpect(t, c, "NS01 CAPABILITY\r\n")
	nativeTCPDiscoverySend(t, c, "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\nNS01 OK done\r\n")
}
func nativeTCPDiscoveryPOP3(t *testing.T, c net.Conn) {
	nativeTCPDiscoverySend(t, c, "+OK Local POP3 <123@local>\r\n")
	nativeTCPDiscoveryExpect(t, c, "CAPA\r\n")
	nativeTCPDiscoverySend(t, c, "+OK capabilities\r\nUSER\r\nIMPLEMENTATION LocalMail 2\r\nSASL PLAIN LOGIN\r\n.\r\n")
}

func nativeTCPDiscoveryProbes() []nativeTCPDiscoveryProbe {
	return []nativeTCPDiscoveryProbe{RDPFingerprinter{}, RDPTLSFingerprinter{}, VNCFingerprinter{}, TelnetFingerprinter{}, EchoFingerprinter{}, FTPFingerprinter{}, SNPPFingerprinter{}, RsyncFingerprinter{}, RTSPFingerprinter{}, IMAPFingerprinter{}, IMAPTLSFingerprinter{}, POP3Fingerprinter{}, POP3TLSFingerprinter{}, SMTPTLSFingerprinter{}}
}

func TestNativeTCPDiscoveryRejectsUnrelatedAndCancels(t *testing.T) {
	for _, probe := range nativeTCPDiscoveryProbes() {
		t.Run(reflect.TypeOf(probe).Name(), func(t *testing.T) {
			t.Run("unrelated", func(t *testing.T) {
				port := nativeTCPDiscoveryListener(t, func(c net.Conn) { _, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n") })
				result, _ := probe.Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 1)
				if result != nil {
					t.Fatal("accepted unrelated service")
				}
			})
			t.Run("cancel-read-or-handshake", func(t *testing.T) {
				accepted := make(chan struct{})
				port := nativeTCPDiscoveryListener(t, func(c net.Conn) { close(accepted); _, _ = io.Copy(io.Discard, c) })
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() {
					result, err := probe.Detect(ctx, net.ParseIP("127.0.0.1"), port, "localhost", -1)
					if result != nil {
						t.Error("canceled probe returned result")
					}
					done <- err
				}()
				select {
				case <-accepted:
				case <-time.After(time.Second):
					t.Fatal("connection not accepted")
				}
				cancel()
				select {
				case err := <-done:
					if err == nil {
						t.Error("missing cancellation error")
					}
				case <-time.After(time.Second):
					t.Fatal("cancellation did not stop probe")
				}
			})
			t.Run("parent-deadline", func(t *testing.T) {
				port := nativeTCPDiscoveryListener(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
				defer cancel()
				start := time.Now()
				result, err := probe.Detect(ctx, net.ParseIP("127.0.0.1"), port, "localhost", 5)
				if result != nil || err == nil || time.Since(start) > time.Second {
					t.Fatalf("deadline result=%v err=%v", result, err)
				}
			})
		})
	}
}

func nativeTCPDiscoveryRDPReply(selected byte) []byte {
	return []byte{3, 0, 0, 19, 14, 0xd0, 0, 0, 0, 0, 0, 2, 0, 8, 0, selected, 0, 0, 0}
}

func TestNativeTCPDiscoveryRDP(t *testing.T) {
	tlsConfig := nativeTCPDiscoveryTLS(t)
	for _, selected := range []byte{0, 1, 2, 8} {
		t.Run(string(rune('0'+selected)), func(t *testing.T) {
			port := nativeTCPDiscoveryListener(t, func(c net.Conn) {
				request := make([]byte, 19)
				if _, err := io.ReadFull(c, request); err != nil {
					t.Error(err)
					return
				}
				want := byte(0)
				if selected != 0 {
					want = 11
				}
				if request[15] != want {
					t.Errorf("requested protocols=%d", request[15])
				}
				nativeTCPDiscoverySend(t, c, string(nativeTCPDiscoveryRDPReply(selected)))
				if selected != 0 {
					secured := tls.Server(c, tlsConfig)
					if err := secured.Handshake(); err != nil {
						t.Error(err)
						return
					}
					if selected == 2 || selected == 8 {
						request, err := readRDPDiscoveryDER(secured)
						if err != nil {
							t.Error(err)
							return
						}
						var decoded rdpDiscoveryRequest
						if _, err = asn1.Unmarshal(request, &decoded); err != nil {
							t.Error(err)
							return
						}
						if len(decoded.Tokens) != 1 || binary.LittleEndian.Uint32(decoded.Tokens[0].Token[8:12]) != 1 || len(decoded.AuthInfo) != 0 {
							t.Error("expected only NTLM negotiate")
						}
						response, _ := asn1.Marshal(rdpDiscoveryRequest{Version: 6, Tokens: []rdpDiscoveryToken{{Token: nativeTCPDiscoveryChallenge()}}})
						nativeTCPDiscoverySend(t, secured, string(response))
					}
				}
			})
			var probe nativeTCPDiscoveryProbe = RDPFingerprinter{}
			if selected != 0 {
				probe = RDPTLSFingerprinter{}
			}
			result, err := probe.Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
			if err != nil {
				t.Fatal(err)
			}
			if result.Protocol != common.ProtocolTypeRdp || result.Transport != common.TransportTypeTcp || result.Tls == nil || *result.Tls != (selected != 0) {
				t.Fatalf("bad RDP result: %#v", result)
			}
			if selected == 2 || selected == 8 {
				meta := result.Metadata.Generic.Metadata
				if meta["osVersion"] != "10.0.20348" || meta["mappedOsVersion"] != "Windows Server 2022" || meta["netBIOSComputerName"] != "HOST" {
					t.Fatalf("missing NTLM metadata: %#v", meta)
				}
			}
		})
	}
}

func nativeTCPDiscoveryChallenge() []byte {
	message := make([]byte, 56)
	copy(message, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(message[8:], 2)
	binary.LittleEndian.PutUint32(message[20:], 0x02800001)
	message[48] = 10
	binary.LittleEndian.PutUint16(message[50:], 20348)
	message[55] = 15
	av := []byte{1, 0, 8, 0, 'H', 0, 'O', 0, 'S', 0, 'T', 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(message[40:], uint16(len(av)))
	binary.LittleEndian.PutUint32(message[44:], 56)
	return append(message, av...)
}

func TestNativeTCPDiscoveryRDPRejectsInvalidFraming(t *testing.T) {
	tests := map[string][]byte{"bare-x224": {3, 0, 0, 11, 6, 0xd0, 0, 0, 0, 0, 0}, "wrong-li": nativeTCPDiscoveryRDPReply(0), "wrong-neg-length": nativeTCPDiscoveryRDPReply(0), "unoffered-tls": nativeTCPDiscoveryRDPReply(1), "reserved": nativeTCPDiscoveryRDPReply(0), "unknown-type": nativeTCPDiscoveryRDPReply(0)}
	tests["wrong-li"][4] = 6
	tests["wrong-neg-length"][13] = 7
	tests["reserved"][1] = 1
	tests["unknown-type"][11] = 4
	for name, response := range tests {
		t.Run(name, func(t *testing.T) {
			port := nativeTCPDiscoveryListener(t, func(c net.Conn) {
				request := make([]byte, 19)
				_, _ = io.ReadFull(c, request)
				_, _ = c.Write(response)
			})
			result, err := (RDPFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 1)
			if result != nil || err == nil {
				t.Fatal("accepted invalid RDP")
			}
		})
	}
}

func TestNativeTCPDiscoveryBoundsAndParsing(t *testing.T) {
	for _, line := range []string{strings.Repeat("x", 8192) + "\r\n", "220 LF only\n", "22\r\n", "220!bad\r\n", "220-more\r\n221 wrong final\r\n"} {
		if _, _, err := readFTPReply(bufio.NewReaderSize(strings.NewReader(line), 4096)); err == nil {
			t.Fatalf("accepted malformed numeric reply %q", line[:min(len(line), 40)])
		}
	}
	for _, raw := range [][]byte{nil, {0x30, 0x80}, {0x30, 0x83, 1, 0, 0}, {0x30, 0x82, 0xff, 0xff}, {0x30, 3, 1}} {
		if _, err := readRDPDiscoveryDER(strings.NewReader(string(raw))); err == nil {
			t.Fatalf("accepted DER %x", raw)
		}
	}
	valid := nativeTCPDiscoveryChallenge()
	for n := 0; n < len(valid); n++ {
		if _, err := parseRDPDiscoveryChallenge(valid[:n]); err == nil {
			t.Fatalf("accepted truncated challenge of length %d", n)
		}
	}
	for _, offset := range []int{12, 40, 44, 58} {
		bad := append([]byte(nil), valid...)
		bad[offset] = 255
		bad[offset+1] = 255
		if _, err := parseRDPDiscoveryChallenge(bad); err == nil {
			t.Fatalf("accepted invalid buffer at %d", offset)
		}
	}
	for _, hasVersion := range []bool{false, true} {
		length := 48
		if hasVersion {
			length = 56
		}
		empty := make([]byte, length)
		copy(empty, "NTLMSSP\x00")
		binary.LittleEndian.PutUint32(empty[8:], 2)
		if hasVersion {
			binary.LittleEndian.PutUint32(empty[20:], 0x02000000)
		}
		// Zero-length buffers may carry ignored offsets outside the message.
		binary.LittleEndian.PutUint32(empty[16:], 0xffffffff)
		binary.LittleEndian.PutUint32(empty[44:], 0xffffffff)
		meta, err := parseRDPDiscoveryChallenge(empty)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"targetName", "netBIOSComputerName", "dnsDomainName"} {
			if meta[key] != "" {
				t.Fatalf("fabricated %s", key)
			}
		}
	}
}

func TestNativeTCPDiscoveryMalformedReplies(t *testing.T) {
	tlsConfig := nativeTCPDiscoveryTLS(t)
	tests := []struct {
		name                     string
		probe                    nativeTCPDiscoveryProbe
		secure                   bool
		greeting, request, reply string
	}{
		{"vnc-digits", VNCFingerprinter{}, false, "RFB 003.abc\n", "", ""},
		{"telnet-truncated-option", TelnetFingerprinter{}, false, "", string([]byte{255, 253, 3}), string([]byte{255, 251})},
		{"echo-static-reply", EchoFingerprinter{}, false, strings.Repeat("x", 128), "", ""},
		{"ftp-smtp-greeting", FTPFingerprinter{}, false, "220 local ESMTP\r\n", "SYST\r\n", "500 Unknown\r\n500 Unknown\r\n"},
		{"snpp-smtp-help", SNPPFingerprinter{}, false, "220 local ESMTP\r\n", "HELP\r\n", "214 SMTP help\r\n250 End\r\n"},
		{"rsync-invalid-version", RsyncFingerprinter{}, false, "@RSYNCD: 31.bad\n", "", ""},
		{"rtsp-wrong-cseq", RTSPFingerprinter{}, false, "", "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: networkscan\r\n\r\n", "RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n"},
		{"imap-wrong-tag", IMAPFingerprinter{}, false, "* OK ready\r\n", "NS01 CAPABILITY\r\n", "* CAPABILITY IMAP4rev1\r\nOTHER OK done\r\n"},
		{"imaps-missing-capability", IMAPTLSFingerprinter{}, true, "* OK ready\r\n", "NS01 CAPABILITY\r\n", "NS01 OK done\r\n"},
		{"pop3-truncated-capa", POP3Fingerprinter{}, false, "+OK ready\r\n", "CAPA\r\n", "+OK capabilities\r\nUSER\r\n"},
		{"pop3s-wrong-status", POP3TLSFingerprinter{}, true, "+OK ready\r\n", "CAPA\r\n", "220 ready\r\n"},
		{"smtps-wrong-continuation", SMTPTLSFingerprinter{}, true, "220 local ESMTP\r\n", "EHLO scanner.local\r\n", "250-local\r\nnot an SMTP line\r\n250 End\r\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			port := nativeTCPDiscoveryListener(t, func(c net.Conn) {
				if test.secure {
					secure := tls.Server(c, tlsConfig)
					if err := secure.Handshake(); err != nil {
						t.Error(err)
						return
					}
					c = secure
				}
				_, _ = io.WriteString(c, test.greeting)
				if test.request != "" {
					nativeTCPDiscoveryExpect(t, c, test.request)
					_, _ = io.WriteString(c, test.reply)
				}
				if test.name == "ftp-smtp-greeting" {
					nativeTCPDiscoveryExpect(t, c, "FEAT\r\n")
				}
			})
			result, err := test.probe.Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 1)
			if result != nil || err == nil {
				t.Fatalf("accepted malformed response: %#v, %v", result, err)
			}
		})
	}
}

func TestNativeTCPDiscoveryRDPOptionalEnrichment(t *testing.T) {
	tlsConfig := nativeTCPDiscoveryTLS(t)
	for _, mode := range []string{"malformed", "deadline", "spnego"} {
		t.Run(mode, func(t *testing.T) {
			port := nativeTCPDiscoveryListener(t, func(c net.Conn) {
				request := make([]byte, 19)
				if _, err := io.ReadFull(c, request); err != nil {
					t.Error(err)
					return
				}
				_, _ = c.Write(nativeTCPDiscoveryRDPReply(2))
				secure := tls.Server(c, tlsConfig)
				if err := secure.Handshake(); err != nil {
					t.Error(err)
					return
				}
				if _, err := readRDPDiscoveryDER(secure); err != nil {
					t.Error(err)
					return
				}
				switch mode {
				case "malformed":
					_, _ = secure.Write([]byte{0x30, 0x80})
				case "deadline":
					_, _ = io.Copy(io.Discard, secure)
				case "spnego":
					wrapped, err := asn1.MarshalWithParams(struct {
						Response []byte `asn1:"explicit,tag:2"`
					}{nativeTCPDiscoveryChallenge()}, "explicit,tag:1")
					if err != nil {
						t.Error(err)
						return
					}
					response, err := asn1.Marshal(rdpDiscoveryRequest{Version: 6, Tokens: []rdpDiscoveryToken{{Token: wrapped}}})
					if err != nil {
						t.Error(err)
						return
					}
					_, _ = secure.Write(response)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			start := time.Now()
			result, err := (RDPTLSFingerprinter{}).Detect(ctx, net.ParseIP("127.0.0.1"), port, "localhost", 3)
			if err != nil || result == nil || result.Tls == nil || !*result.Tls {
				t.Fatalf("lost established RDP proof: %v", err)
			}
			if time.Since(start) > time.Second {
				t.Fatal("enrichment ignored context budget")
			}
			meta := result.Metadata.Generic.Metadata
			if mode == "spnego" {
				if meta["osVersion"] != "10.0.20348" {
					t.Fatalf("missing wrapped NTLM metadata: %v", meta)
				}
			} else if meta["osVersion"] != "" || meta["fingerprint"] != "" {
				t.Fatal("fabricated OS metadata")
			}
		})
	}
}
