package plugins

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"golang.org/x/text/encoding/charmap"
)

type nativeDatabaseDetector interface {
	Name() string
	DefaultPorts() []int
	Detect(context.Context, net.IP, int, string, int) (*discover.ServiceDetails, error)
}

func nativeDatabaseListener(t *testing.T, secure bool, serve func(net.Conn)) (net.IP, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if secure {
		certificateServer := httptest.NewTLSServer(nil)
		config := &tls.Config{Certificates: certificateServer.TLS.Certificates, MinVersion: tls.VersionTLS12}
		certificateServer.Close()
		listener = tls.NewListener(listener, config)
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
			t.Error("database fixture did not exit")
		}
	})
	address := listener.Addr().(*net.TCPAddr)
	return address.IP, address.Port
}

func nativeDatabaseTDS(body []byte) []byte {
	h := []byte{4, 1, 0, 0, 0, 0, 1, 0}
	binary.BigEndian.PutUint16(h[2:], uint16(len(body)+8))
	return append(h, body...)
}

func nativeDatabasePG(kind byte, body []byte) []byte {
	h := make([]byte, 5)
	h[0] = kind
	binary.BigEndian.PutUint32(h[1:], uint32(len(body)+4))
	return append(h, body...)
}

func nativeDatabaseMySQL() []byte {
	b := append([]byte{10}, []byte("8.4.2-local\x00")...)
	// Connection id, first salt, filler, lower capabilities, charset, status,
	// upper capabilities, auth data length, and ten reserved bytes.
	b = append(b, 1, 0, 0, 0)
	b = append(b, []byte("12345678")...)
	b = append(b, 0, 0, 0x8a, 45, 2, 0, 8, 0, 21)
	b = append(b, make([]byte, 10)...)
	b = append(b, []byte("abcdefghijkl\x00caching_sha2_password\x00")...)
	return append([]byte{byte(len(b)), byte(len(b) >> 8), 0, 0}, b...)
}

func nativeDatabaseDRDA() []byte {
	var fields []byte
	for _, f := range []struct {
		code  uint16
		value string
	}{{0x1147, "DB2/LINUXX8664"}, {0x115a, "SQL11050"}, {0x116d, "LABDB"}} {
		value, _ := charmap.CodePage037.NewEncoder().Bytes([]byte(f.value))
		field := make([]byte, 4)
		binary.BigEndian.PutUint16(field, uint16(4+len(value)))
		binary.BigEndian.PutUint16(field[2:], f.code)
		fields = append(fields, append(field, value...)...)
	}
	b := make([]byte, 10)
	binary.BigEndian.PutUint16(b, uint16(10+len(fields)))
	b[2] = 0xd0
	b[3] = 2
	b[5] = 1
	binary.BigEndian.PutUint16(b[6:], uint16(4+len(fields)))
	binary.BigEndian.PutUint16(b[8:], 0x1443)
	return append(b, fields...)
}

func nativeDatabaseFirebird(op, version uint32) []byte {
	var b []byte
	for _, v := range []uint32{op, version, 1, 3} {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	if op != 3 {
		b = binary.BigEndian.AppendUint32(b, 0)
		b = binary.BigEndian.AppendUint32(b, 3)
		b = append(b, 'S', 'r', 'p', 0)
		b = binary.BigEndian.AppendUint32(b, 0)
		b = binary.BigEndian.AppendUint32(b, 0)
	}
	return b
}

func nativeDatabaseSybase() []byte {
	message := []byte("Type '18' not allowed before login.")
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b, 1621)
	b[4] = 1
	b[5] = 18
	binary.LittleEndian.PutUint16(b[6:], uint16(len(message)))
	b = append(b, message...)
	b = append(b, 3, 'A', 'S', 'E', 0, 1, 0)
	token := []byte{0xaa, byte(len(b)), byte(len(b) >> 8)}
	return nativeDatabaseTDS(append(token, b...))
}

func TestNativeDatabaseInventory(t *testing.T) {
	tests := []struct {
		d     nativeDatabaseDetector
		name  string
		ports []int
	}{
		{DB2Fingerprinter{}, "db2", []int{446, 50000}}, {FirebirdFingerprinter{}, "firebird", []int{3050}},
		{MSSQLFingerprinter{}, "mssql", []int{1433}}, {MySQLFingerprinter{}, "MySQL", []int{3306}},
		{PostgresFingerprinter{}, "postgres", []int{5432}}, {SybaseFingerprinter{}, "sybase", []int{5000}},
		{RedisTLSFingerprinter{}, "redis", []int{6380}},
	}
	for _, tt := range tests {
		if tt.d.Name() != tt.name || !reflect.DeepEqual(tt.d.DefaultPorts(), tt.ports) {
			t.Errorf("%T inventory changed", tt.d)
		}
	}
}

func nativeDatabaseReadProbe(t *testing.T, c net.Conn, kind string) {
	t.Helper()
	switch kind {
	case "mysql":
		return
	case "mssql", "sybase":
		var h [8]byte
		if _, err := io.ReadFull(c, h[:]); err != nil {
			t.Error(err)
			return
		}
		n := int(binary.BigEndian.Uint16(h[2:]))
		if h[0] != 0x12 || n != 26 {
			t.Errorf("not credential-free PRELOGIN: %x", h)
			return
		}
		_, _ = io.CopyN(io.Discard, c, int64(n-8))
	case "postgres":
		var h [4]byte
		if _, err := io.ReadFull(c, h[:]); err != nil {
			t.Error(err)
			return
		}
		n := int(binary.BigEndian.Uint32(h[:]))
		if n < 8 || n > 1024 {
			t.Errorf("bad startup size %d", n)
			return
		}
		b := make([]byte, n-4)
		_, _ = io.ReadFull(c, b)
		if binary.BigEndian.Uint32(b) != 196608 || !bytes.Contains(b, []byte("user\x00networkscan\x00")) {
			t.Errorf("bad startup %q", b)
		}
	case "db2":
		var h [10]byte
		if _, err := io.ReadFull(c, h[:]); err != nil {
			t.Error(err)
			return
		}
		n := int(binary.BigEndian.Uint16(h[:]))
		if n < 10 || n > 4096 || binary.BigEndian.Uint16(h[8:]) != 0x1041 {
			t.Errorf("not EXCSAT: %x", h)
			return
		}
		_, _ = io.CopyN(io.Discard, c, int64(n-10))
	case "firebird":
		var b [228]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			t.Error(err)
			return
		}
		// Firebird wire specification 5.2: op_connect, unused operation zero,
		// CONNECT_VERSION3, arch_generic, XDR empty target, count, empty identity.
		wantHeader := []uint32{1, 0, 3, 1, 0, 10, 0}
		for i, want := range wantHeader {
			if got := binary.BigEndian.Uint32(b[i*4:]); got != want {
				t.Errorf("connect field %d=%d, want %d", i, got, want)
			}
		}
		for i := 0; i < 10; i++ {
			p := 28 + 20*i
			wire := binary.BigEndian.Uint32(b[p:])
			version := wire & 0x7fff
			if version != uint32(10+i) || (version > 10 && wire&0x8000 == 0) {
				t.Errorf("invalid offered protocol %x", wire)
			}
			if binary.BigEndian.Uint32(b[p+4:]) != 1 || binary.BigEndian.Uint32(b[p+8:]) != 3 || binary.BigEndian.Uint32(b[p+12:]) != 5 {
				t.Error("invalid architecture or connection type range")
			}
			if binary.BigEndian.Uint32(b[p+16:]) == 0 {
				t.Error("missing protocol weight")
			}
		}
	case "redis":
		b := make([]byte, len("*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"))
		if _, err := io.ReadFull(c, b); err != nil {
			t.Error(err)
			return
		}
		if string(b) != "*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n" {
			t.Errorf("not INFO: %q", b)
		}
	}
}

func TestNativeDatabaseLoopback(t *testing.T) {
	prelogin := []byte{0, 0, 11, 0, 6, 1, 0, 17, 0, 1, 255, 16, 0, 0x10, 0x01, 0, 0, 3}
	info := "# Server\r\nredis_version:7.4.1\r\nredis_mode:standalone\r\n"
	tests := []struct {
		kind                string
		d                   nativeDatabaseDetector
		reply               []byte
		version, key, value string
	}{
		{"mysql", MySQLFingerprinter{}, nativeDatabaseMySQL(), "8.4.2-local", "packetType", "handshake"},
		{"mysql", MySQLFingerprinter{}, append([]byte{20, 0, 0, 0, 255, 0x15, 4}, []byte("Access denied now")...), "", "authRequired", "true"},
		{"mssql", MSSQLFingerprinter{}, nativeDatabaseTDS(prelogin), "16.0.4097", "encryptionRequired", "true"},
		{"postgres", PostgresFingerprinter{}, nativeDatabasePG('R', []byte{0, 0, 0, 5, 1, 2, 3, 4}), "", "authRequired", "true"},
		{"postgres", PostgresFingerprinter{}, nativeDatabasePG('R', append([]byte{0, 0, 0, 10}, []byte("SCRAM-SHA-256\x00\x00")...)), "", "authenticationMethod", "10"},
		{"postgres", PostgresFingerprinter{}, append(append(nativeDatabasePG('R', []byte{0, 0, 0, 0}), nativeDatabasePG('S', []byte("server_version\x0017.3\x00"))...), nativeDatabasePG('Z', []byte{'I'})...), "17.3", "authRequired", "false"},
		{"postgres", PostgresFingerprinter{}, nativeDatabasePG('E', []byte("SFATAL\x00C28000\x00Mno pg_hba.conf entry\x00\x00")), "", "authRequired", "true"},
		{"db2", DB2Fingerprinter{}, nativeDatabaseDRDA(), "11.5.0", "serverName", "LABDB"},
		{"firebird", FirebirdFingerprinter{}, nativeDatabaseFirebird(3, 0x800c), "", "protocol_version", "32780"},
		{"firebird", FirebirdFingerprinter{}, nativeDatabaseFirebird(98, 0x8012), "", "authRequired", "true"},
		{"sybase", SybaseFingerprinter{}, nativeDatabaseSybase(), "", "authRequired", "true"},
		{"redis", RedisTLSFingerprinter{}, []byte(fmt.Sprintf("$%d\r\n%s\r\n", len(info), info)), "7.4.1", "authRequired", "false"},
		{"redis", RedisTLSFingerprinter{}, []byte("-NOAUTH Authentication required.\r\n"), "", "authRequired", "true"},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("%s-%d", tt.kind, i), func(t *testing.T) {
			ip, port := nativeDatabaseListener(t, tt.kind == "redis", func(c net.Conn) {
				nativeDatabaseReadProbe(t, c, tt.kind)
				// One-byte writes exercise arbitrary TCP/TLS record fragmentation.
				for _, b := range tt.reply {
					if _, err := c.Write([]byte{b}); err != nil {
						return
					}
				}
				var extra [1]byte
				n, err := c.Read(extra[:])
				if n != 0 || err != io.EOF {
					t.Errorf("probe continued after discovery: %d %v", n, err)
				}
			})
			result, err := tt.d.Detect(context.Background(), ip, port, "localhost", 2)
			if err != nil || result == nil {
				t.Fatalf("detection: %v", err)
			}
			if result.Version == nil || *result.Version != tt.version {
				t.Errorf("version %v, want %q", result.Version, tt.version)
			}
			if result.Metadata.Generic.Metadata[tt.key] != tt.value {
				t.Errorf("metadata: %v", result.Metadata.Generic.Metadata)
			}
			if result.Transport != common.TransportTypeTcp {
				t.Error("transport is not TCP")
			}
			if tt.kind == "redis" && (result.Tls == nil || !*result.Tls) {
				t.Error("TLS signal absent")
			}
		})
	}
}

func TestNativeDatabaseNegativeAndCancellation(t *testing.T) {
	tests := []nativeDatabaseDetector{DB2Fingerprinter{}, FirebirdFingerprinter{}, MSSQLFingerprinter{}, MySQLFingerprinter{}, PostgresFingerprinter{}, SybaseFingerprinter{}, RedisTLSFingerprinter{}}
	for _, d := range tests {
		t.Run(fmt.Sprintf("%T", d), func(t *testing.T) {
			t.Run("negative", func(t *testing.T) {
				_, secure := d.(RedisTLSFingerprinter)
				ip, port := nativeDatabaseListener(t, secure, func(c net.Conn) { _, _ = c.Write([]byte("HTTP/1.0 200 OK\r\n\r\n")) })
				result, err := d.Detect(context.Background(), ip, port, "localhost", 1)
				if result != nil || err == nil {
					t.Errorf("accepted unrelated service: %v %v", result, err)
				}
			})
			t.Run("cancel-inflight", func(t *testing.T) {
				accepted := make(chan struct{})
				ip, port := nativeDatabaseListener(t, false, func(c net.Conn) { close(accepted); _, _ = io.Copy(io.Discard, c) })
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() {
					result, err := d.Detect(ctx, ip, port, "localhost", -1)
					if result != nil {
						done <- fmt.Errorf("unexpected result")
						return
					}
					done <- err
				}()
				select {
				case <-accepted:
				case <-time.After(time.Second):
					t.Fatal("not connected")
				}
				cancel()
				select {
				case err := <-done:
					if err == nil {
						t.Error("cancellation had no error")
					}
				case <-time.After(time.Second):
					t.Fatal("cancellation did not close connection")
				}
			})
			t.Run("deadline", func(t *testing.T) {
				ip, port := nativeDatabaseListener(t, false, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
				defer cancel()
				start := time.Now()
				result, err := d.Detect(ctx, ip, port, "localhost", -1)
				if result != nil || err == nil || time.Since(start) > time.Second {
					t.Errorf("deadline not honored: %v", err)
				}
			})
		})
	}
}

func TestNativeDatabaseMalformedParsers(t *testing.T) {
	t.Run("mysql-optional-section", func(t *testing.T) {
		body := nativeDatabaseMySQL()[4:]
		p := bytes.IndexByte(body[1:], 0) + 2
		for n := p + 16; n < p+31; n++ {
			if _, _, err := mysqlGreeting(body[:n]); err == nil {
				t.Errorf("accepted truncated fixed greeting at %d", n)
			}
		}
		if _, _, err := mysqlGreeting(body[:p+15]); err != nil {
			t.Errorf("legal short greeting: %v", err)
		}
		if _, _, err := mysqlGreeting([]byte{255, 1, 0, 'x'}); err == nil {
			t.Error("accepted bad error")
		}
	})
	t.Run("tds", func(t *testing.T) {
		for _, b := range [][]byte{{0, 0, 0, 0, 6, 255, 1, 2, 3, 4, 5, 6}, {0, 255, 255, 0, 6, 255}, {0, 0, 6, 0, 6, 255, 1, 2, 3, 4, 5, 6}} {
			if _, _, err := mssqlOptions(b); err == nil {
				t.Errorf("accepted malformed options %x", b)
			}
		}
		for _, b := range [][]byte{{4, 1, 0, 7, 0, 0, 0, 0}, {4, 1, 255, 255, 0, 0, 0, 0}, {4, 0, 0, 8, 0, 0, 0, 0}} {
			if _, err := databaseTDSReply(bytes.NewReader(b)); err == nil {
				t.Error("accepted invalid frame")
			}
		}
		packet := append([]byte{4, 0, 0, 10, 0, 0, 1, 0, 1, 2}, []byte{4, 1, 0, 10, 0, 0, 2, 0, 3, 4}...)
		got, err := databaseTDSReply(bytes.NewReader(packet))
		if err != nil || !bytes.Equal(got, []byte{1, 2, 3, 4}) {
			t.Fatalf("fragment assembly: %x %v", got, err)
		}
	})
	t.Run("postgres", func(t *testing.T) {
		for _, b := range [][]byte{nativeDatabasePG('R', []byte{0, 0, 0, 5}), nativeDatabasePG('R', []byte{0, 0, 0, 11}), nativeDatabasePG('E', []byte("Merror\x00\x00")), {'R', 0xff, 0xff, 0xff, 0xff}, nativeDatabasePG('S', []byte("server_version\x0017\x00"))} {
			if _, _, err := postgresStartupReply(bytes.NewReader(b)); err == nil {
				t.Errorf("accepted malformed PG %x", b)
			}
		}
	})
	t.Run("db2", func(t *testing.T) {
		valid := nativeDatabaseDRDA()[6:]
		for n := 0; n < len(valid); n++ {
			if _, _, err := db2Attributes(valid[:n]); err == nil {
				t.Errorf("accepted DRDA truncation %d", n)
			}
		}
		invalid := append([]byte(nil), valid...)
		invalid[4] = 0xff
		invalid[5] = 0xff
		if _, _, err := db2Attributes(invalid); err == nil {
			t.Error("accepted overflowing parameter")
		}
	})
	t.Run("firebird", func(t *testing.T) {
		for _, b := range [][]byte{nativeDatabaseFirebird(3, 19), nativeDatabaseFirebird(98, 10), {0, 0, 0, 4}, nativeDatabaseFirebird(98, 0x8012)[:17]} {
			if _, err := firebirdAccept(bytes.NewReader(b)); err == nil {
				t.Error("accepted invalid Firebird")
			}
		}
		if _, err := firebirdBuffer(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff})); err == nil {
			t.Error("accepted unbounded XDR")
		}
	})
	t.Run("sybase", func(t *testing.T) {
		valid := nativeDatabaseSybase()[8:]
		for n := 0; n < len(valid); n++ {
			if _, err := sybasePreauthError(valid[:n]); err == nil {
				t.Errorf("accepted truncation %d", n)
			}
		}
		invalid := append([]byte(nil), valid...)
		invalid[3] = 0
		if _, err := sybasePreauthError(invalid); err == nil {
			t.Error("accepted other TDS error")
		}
	})
}

func TestNativeDatabaseRedisTLSBounds(t *testing.T) {
	for _, reply := range []string{"$65537\r\n", "$-1\r\n", "$3\r\nfooXX", "+PONG\n", strings.Repeat("x", 4097) + "\r\n"} {
		t.Run(fmt.Sprintf("length-%d", len(reply)), func(t *testing.T) {
			ip, port := nativeDatabaseListener(t, true, func(c net.Conn) { nativeDatabaseReadProbe(t, c, "redis"); _, _ = io.WriteString(c, reply) })
			result, err := (RedisTLSFingerprinter{}).Detect(context.Background(), ip, port, "localhost", 1)
			if result != nil || err == nil {
				t.Errorf("accepted malformed RESP %q", reply)
			}
		})
	}
}

func TestNativeDatabaseAdditionalProtocolVariants(t *testing.T) {
	t.Run("mysql-nine", func(t *testing.T) {
		b := append([]byte{9}, []byte("3.23.58\x00")...)
		b = append(b, 1, 0, 0, 0)
		b = append(b, []byte("challenge\x00")...)
		v, m, err := mysqlGreeting(b)
		if err != nil || v != "3.23.58" || m["protocolVersion"] != "9" {
			t.Fatalf("v9: %s %v %v", v, m, err)
		}
	})
	t.Run("mysql-truncated-salt", func(t *testing.T) {
		b := nativeDatabaseMySQL()[4:]
		p := bytes.IndexByte(b[1:], 0) + 2
		for n := p + 31; n < p+44; n++ {
			if _, _, err := mysqlGreeting(b[:n]); err == nil {
				t.Errorf("accepted salt truncation %d", n)
			}
		}
	})
	t.Run("firebird-status", func(t *testing.T) {
		var b []byte
		for _, v := range []uint32{9, 0, 0, 0, 0, 1, 335544472, 0} {
			b = binary.BigEndian.AppendUint32(b, v)
		}
		ip, port := nativeDatabaseListener(t, false, func(c net.Conn) { nativeDatabaseReadProbe(t, c, "firebird"); _, _ = c.Write(b) })
		result, err := (FirebirdFingerprinter{}).Detect(context.Background(), ip, port, "localhost", 1)
		if err != nil || result == nil || result.Metadata.Generic.Metadata["authRequired"] != "true" {
			t.Fatalf("status: %v %v", result, err)
		}
		for n := 0; n < len(b); n++ {
			if _, err := firebirdAccept(bytes.NewReader(b[:n])); err == nil {
				t.Errorf("accepted status truncation %d", n)
			}
		}
	})
	t.Run("sybase-localized-eed", func(t *testing.T) {
		message := []byte("Operation avant connexion interdite.")
		b := make([]byte, 6)
		binary.LittleEndian.PutUint32(b, 1621)
		b[4] = 1
		b[5] = 18
		// EED adds SQLSTATE, status, and transaction state ahead of the message.
		b = append(b, 5, 'Z', 'Z', 'Z', 'Z', 'Z', 0, 0, 0)
		b = binary.LittleEndian.AppendUint16(b, uint16(len(message)))
		b = append(b, message...)
		b = append(b, 3, 'A', 'S', 'E', 0, 0, 0)
		token := []byte{0xe5}
		token = binary.LittleEndian.AppendUint16(token, uint16(len(b)))
		token = append(token, b...)
		ip, port := nativeDatabaseListener(t, false, func(c net.Conn) { nativeDatabaseReadProbe(t, c, "sybase"); _, _ = c.Write(nativeDatabaseTDS(token)) })
		result, err := (SybaseFingerprinter{}).Detect(context.Background(), ip, port, "localhost", 1)
		if err != nil || result == nil || result.Metadata.Generic.Metadata["errorMsg"] != string(message) {
			t.Fatalf("localized EED: %v %v", result, err)
		}
	})
	t.Run("redis-ping-fallback", func(t *testing.T) {
		ip, port := nativeDatabaseListener(t, true, func(c net.Conn) {
			nativeDatabaseReadProbe(t, c, "redis")
			_, _ = io.WriteString(c, "-NOPERM command denied\r\n")
			want := "*1\r\n$4\r\nPING\r\n"
			b := make([]byte, len(want))
			_, _ = io.ReadFull(c, b)
			if string(b) != want {
				t.Errorf("expected PING, got %q", b)
			}
			_, _ = io.WriteString(c, "+PONG\r\n")
		})
		result, err := (RedisTLSFingerprinter{}).Detect(context.Background(), ip, port, "localhost", 1)
		if err != nil || result == nil || result.Metadata.Generic.Metadata["state"] != "pong" {
			t.Fatalf("PING: %v %v", result, err)
		}
	})
}
