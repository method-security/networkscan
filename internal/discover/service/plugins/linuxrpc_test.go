package plugins

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func nativeRPCFixture(request []byte) []byte {
	b := nativeBinaryWords(binary.BigEndian.Uint32(request[4:]), 1, 0, 0, 0, 0, 1, 100003, 4)
	for _, s := range []string{"tcp", "127.0.0.1.8.1", "root"} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
		b = append(b, s...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
	}
	b = binary.BigEndian.AppendUint32(b, 0)
	return append(nativeBinaryWords(0x80000000|uint32(len(b))), b...)
}

func TestNativeBinaryRPC(t *testing.T) {
	nativeBinaryCases(t, RPCFingerprinter{}, func(request []byte) []byte {
		if string(request[8:]) != string(nativeBinaryWords(0, 2, 100000, 4, 4, 0, 0, 0, 0)) {
			t.Error("expected rpcbind v4 DUMP AUTH_NONE")
		}
		return nativeRPCFixture(request)
	}, map[string]func([]byte) []byte{
		"wrong_xid":             func(b []byte) []byte { b[7] ^= 1; return b },
		"call_instead_of_reply": func(b []byte) []byte { b[11] = 0; return b },
		"denied":                func(b []byte) []byte { b[15] = 1; return b },
		"oversized_record":      func(b []byte) []byte { binary.BigEndian.PutUint32(b, 0xffffffff); return b[:4] },
		"oversized_verifier":    func(b []byte) []byte { binary.BigEndian.PutUint32(b[20:], 401); return b },
		"failed_procedure":      func(b []byte) []byte { b[27] = 3; return b },
		"invalid_list_bool":     func(b []byte) []byte { b[31] = 2; return b },
		"huge_string":           func(b []byte) []byte { binary.BigEndian.PutUint32(b[40:], 0xffffffff); return b },
		"bad_padding":           func(b []byte) []byte { b[47] = 1; return b },
		"truncated":             func(b []byte) []byte { return b[:len(b)-1] },
	}, map[string]string{"entries": "[{\"program\":100003,\"version\":4,\"protocol\":\"tcp\",\"address\":\"127.0.0.1.8.1\",\"owner\":\"root\"}]"})
}

func TestNativeBinaryRPCFragments(t *testing.T) {
	nativeBinaryCases(t, RPCFingerprinter{}, func(request []byte) []byte {
		b := nativeRPCFixture(request)[4:]
		first := append(nativeBinaryWords(13), b[:13]...)
		first = append(first, nativeBinaryWords(0x80000000|uint32(len(b)-13))...)
		return append(first, b[13:]...)
	}, map[string]func([]byte) []byte{
		"too_many_fragments": func([]byte) []byte { return make([]byte, 33*4) },
	}, map[string]string{"rpcbindVersion": "4"})
	nativeBinaryCases(t, RPCFingerprinter{}, func(request []byte) []byte {
		return append(nativeBinaryWords(0x8000001c), nativeBinaryWords(binary.BigEndian.Uint32(request[4:]), 1, 0, 0, 0, 0, 0)...)
	}, map[string]func([]byte) []byte{}, map[string]string{"entries": "[]"})
}

func nativeRPCMismatch(request []byte, low, high uint32) []byte {
	body := nativeBinaryWords(binary.BigEndian.Uint32(request[4:]), 1, 0, 0, 0, 2, low, high)
	return append(nativeBinaryWords(0x80000000|uint32(len(body))), body...)
}

func TestNativeBinaryRPCVersionFallback(t *testing.T) {
	for _, mode := range []string{"success", "stale_xid", "second_mismatch", "cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 200*time.Millisecond)
				defer stop()
			}
			port := nativeBinaryServe(t, func(conn net.Conn) {
				first := nativeBinaryRequest(t, conn, "RPC")
				if first == nil {
					return
				}
				if binary.BigEndian.Uint32(first[20:]) != 4 {
					t.Error("first DUMP must request v4")
				}
				if _, err := conn.Write(nativeRPCMismatch(first, 2, 3)); err != nil {
					t.Error(err)
					return
				}
				second := nativeBinaryRequest(t, conn, "RPC")
				if second == nil {
					return
				}
				if binary.BigEndian.Uint32(second[20:]) != 3 || binary.BigEndian.Uint32(second[4:]) == binary.BigEndian.Uint32(first[4:]) {
					t.Error("fallback must request v3 with a new XID")
				}
				switch mode {
				case "cancel", "deadline":
					if mode == "cancel" {
						cancel()
					}
					_, _ = io.Copy(io.Discard, conn)
				case "stale_xid":
					_, _ = conn.Write(nativeRPCFixture(first))
				case "second_mismatch":
					_, _ = conn.Write(nativeRPCMismatch(second, 2, 3))
					var extra [1]byte
					if n, _ := conn.Read(extra[:]); n != 0 {
						t.Error("unexpected third request")
					}
				default:
					_, _ = conn.Write(nativeRPCFixture(second))
				}
			})
			start := time.Now()
			result, err := (RPCFingerprinter{}).Detect(ctx, net.ParseIP("127.0.0.1"), port, "localhost", 2)
			if mode == "success" {
				if err != nil || result == nil {
					t.Fatalf("v3 fallback failed: %v", err)
				}
				if result.Metadata.Generic.Metadata["rpcbindVersion"] != "3" {
					t.Fatal("wrong negotiated version")
				}
				return
			}
			if err == nil || result != nil {
				t.Fatalf("accepted invalid fallback: %+v, %v", result, err)
			}
			if (mode == "cancel" || mode == "deadline") && time.Since(start) > time.Second {
				t.Fatal("fallback exceeded shared context budget")
			}
		})
	}
}

func TestNativeBinaryRPCInvalidMismatch(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"wrong_xid":                func(b []byte) []byte { b[7] ^= 1; return b },
		"denied":                   func(b []byte) []byte { b[15] = 1; return b },
		"other_status":             func(b []byte) []byte { b[27] = 1; return b },
		"reversed_range":           func(b []byte) []byte { b[31] = 5; return b },
		"v2_only":                  func(b []byte) []byte { b[35] = 2; return b },
		"contradictory_v4_support": func(b []byte) []byte { b[35] = 4; return b },
		"short_body":               func(b []byte) []byte { b = b[:32]; binary.BigEndian.PutUint32(b, 0x8000001c); return b },
		"trailing_body":            func(b []byte) []byte { b = append(b, 0, 0, 0, 0); binary.BigEndian.PutUint32(b, 0x80000024); return b },
		"invalid_verifier":         func(b []byte) []byte { b[23] = 4; return b },
	} {
		t.Run(name, func(t *testing.T) {
			port := nativeBinaryServe(t, func(conn net.Conn) {
				request := nativeBinaryRequest(t, conn, "RPC")
				if request == nil {
					return
				}
				_, _ = conn.Write(mutate(nativeRPCMismatch(request, 2, 3)))
				var extra [1]byte
				if n, _ := conn.Read(extra[:]); n != 0 {
					t.Error("invalid mismatch triggered fallback")
				}
			})
			result, err := (RPCFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
			if err == nil || result != nil {
				t.Fatalf("accepted invalid mismatch: %+v, %v", result, err)
			}
		})
	}
}
