package plugins

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type nativeBinaryDetector interface {
	Name() string
	DefaultPorts() []int
	Detect(context.Context, net.IP, int, string, int) (*discoverfern.ServiceDetails, error)
}

func nativeBinaryWords(words ...uint32) []byte {
	var b []byte
	for _, word := range words {
		b = binary.BigEndian.AppendUint32(b, word)
	}
	return b
}

// The fixtures use protocol fields directly and do not call production encoders.
func nativeBinaryServe(t *testing.T, fn func(net.Conn)) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		fn(conn)
	}()
	t.Cleanup(func() { _ = l.Close(); <-done })
	return l.Addr().(*net.TCPAddr).Port
}

func nativeBinaryRequest(t *testing.T, conn net.Conn, protocol string) []byte {
	t.Helper()
	size := map[string]int{"diameter": 20, "smpp": 16, "modbus": 7, "RPC": 4, "jdwp": 11}[protocol]
	if protocol == "jdwp" {
		hello := make([]byte, 14)
		if _, err := io.ReadFull(conn, hello); err != nil {
			t.Error(err)
			return nil
		}
		if string(hello) != "JDWP-Handshake" {
			t.Error("unexpected handshake")
			return nil
		}
		if _, err := conn.Write(hello); err != nil {
			t.Error(err)
			return nil
		}
	}
	header := make([]byte, size)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Error(err)
		return nil
	}
	total := size
	switch protocol {
	case "diameter":
		total = int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	case "smpp", "jdwp":
		total = int(binary.BigEndian.Uint32(header))
	case "modbus":
		total = 6 + int(binary.BigEndian.Uint16(header[4:]))
	case "RPC":
		total = 4 + int(binary.BigEndian.Uint32(header)&0x7fffffff)
	}
	if total < size || total > 4096 {
		t.Errorf("invalid request length %d", total)
		return nil
	}
	request := append(header, make([]byte, total-size)...)
	if _, err := io.ReadFull(conn, request[size:]); err != nil {
		t.Error(err)
		return nil
	}
	return request
}

func nativeBinaryCases(t *testing.T, detector nativeBinaryDetector, response func([]byte) []byte, cases map[string]func([]byte) []byte, want map[string]string) {
	t.Helper()
	cases["valid"] = func(b []byte) []byte { return b }
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			port := nativeBinaryServe(t, func(conn net.Conn) {
				request := nativeBinaryRequest(t, conn, detector.Name())
				if request == nil {
					return
				}
				b := mutate(response(request))
				for len(b) > 0 {
					n := min(3, len(b))
					if _, err := conn.Write(b[:n]); err != nil {
						return
					}
					b = b[n:]
				}
			})
			result, err := detector.Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
			if name != "valid" {
				if err == nil || result != nil {
					t.Fatalf("accepted invalid response: %+v, %v", result, err)
				}
				return
			}
			if err != nil || result == nil {
				t.Fatalf("detection failed: %v", err)
			}
			if result.Transport != common.TransportTypeTcp || result.Host != "localhost" || result.Port != port {
				t.Fatalf("wrong endpoint: %+v", result)
			}
			for key, value := range want {
				if got := result.Metadata.Generic.Metadata[key]; got != value {
					t.Errorf("metadata %s = %q, want %q", key, got, value)
				}
			}
		})
	}
}

func TestNativeBinaryInventoryAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		detector nativeBinaryDetector
		name     string
		ports    []int
	}{
		{DiameterFingerprinter{}, "diameter", []int{3868}}, {SMPPFingerprinter{}, "smpp", []int{2775, 2776}},
		{ModbusFingerprinter{}, "modbus", []int{502}}, {RPCFingerprinter{}, "RPC", []int{111}},
		{JDWPFingerprinter{}, "jdwp", []int{3999, 5000, 5005, 8000, 8453, 8787, 8788, 9001, 18000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.detector.Name() != tc.name || !reflect.DeepEqual(tc.detector.DefaultPorts(), tc.ports) {
				t.Fatal("inventory changed")
			}
			for _, mode := range []string{"cancel", "deadline", "timeout"} {
				t.Run(mode, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					timeout := -1
					if mode == "deadline" {
						var stop context.CancelFunc
						ctx, stop = context.WithTimeout(ctx, 100*time.Millisecond)
						defer stop()
					}
					if mode == "timeout" {
						timeout = 1
					}
					port := nativeBinaryServe(t, func(conn net.Conn) {
						// Consume just the initial byte so even a stalled JDWP handshake is cancellable.
						if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
							return
						}
						if mode == "cancel" {
							cancel()
						}
						_, _ = io.Copy(io.Discard, conn)
					})
					start := time.Now()
					result, err := tc.detector.Detect(ctx, net.ParseIP("127.0.0.1"), port, "localhost", timeout)
					if result != nil || err == nil || time.Since(start) > 2*time.Second {
						t.Fatalf("did not stop promptly: %v", err)
					}
				})
			}
		})
	}
}

func nativeDiameterFixture(request []byte) []byte {
	b := append([]byte(nil), request[:20]...)
	b[4] = 0
	for _, avp := range []struct {
		code  uint32
		value []byte
	}{
		{268, nativeBinaryWords(2001)}, {264, []byte("peer.example")}, {296, []byte("example")},
		{269, []byte("Test Diameter")}, {266, nativeBinaryWords(123)}, {267, nativeBinaryWords(42)},
	} {
		b = binary.BigEndian.AppendUint32(b, avp.code)
		b = append(b, 0x40, 0, 0, byte(8+len(avp.value)))
		b = append(b, avp.value...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
	}
	b[1], b[2], b[3] = byte(len(b)>>16), byte(len(b)>>8), byte(len(b))
	return b
}

func TestNativeBinaryDiameter(t *testing.T) {
	nativeBinaryCases(t, DiameterFingerprinter{}, nativeDiameterFixture, map[string]func([]byte) []byte{
		"wrong_id":          func(b []byte) []byte { b[12] ^= 1; return b },
		"wrong_end_id":      func(b []byte) []byte { b[16] ^= 1; return b },
		"wrong_command":     func(b []byte) []byte { b[7] = 2; return b },
		"wrong_application": func(b []byte) []byte { b[11] = 1; return b },
		"request_bit":       func(b []byte) []byte { b[4] = 0x80; return b },
		"oversized":         func(b []byte) []byte { b[1] = 2; return b[:20] },
		"short_length":      func(b []byte) []byte { b[3] = 16; return b[:20] },
		"bad_avp_length":    func(b []byte) []byte { b[27] = 7; return b },
		"bad_integer":       func(b []byte) []byte { b[27] = 11; return b },
		"missing_result":    func(b []byte) []byte { b[23] = 1; return b },
		"truncated":         func(b []byte) []byte { return b[:len(b)-1] },
	}, map[string]string{"product": "Test Diameter", "version": "42", "vendorID": "123", "originHost": "peer.example", "resultCode": "2001"})
}
