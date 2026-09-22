package stun

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

func testResponse(attributes []byte) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b, 0x0101)
	binary.BigEndian.PutUint16(b[2:], uint16(len(attributes)))
	binary.BigEndian.PutUint32(b[4:], 0x2112a442)
	return append(b, attributes...)
}

func paddedAttributes() []byte {
	return []byte{
		0x80, 0x22, 0, 3, 'a', 'b', 'c', 0xff,
		0x80, 0xff, 0, 2, 0x12, 0x34, 0xee, 0xdd,
	}
}

func TestParseResponseLengths(t *testing.T) {
	for length := 4; length <= 40; length += 4 {
		t.Run(fmt.Sprintf("missing-payload-%d", length), func(t *testing.T) {
			b := testResponse(nil)
			binary.BigEndian.PutUint16(b[2:], uint16(length))
			if _, err := parseResponse(b); err == nil {
				t.Fatal("accepted header without declared payload")
			}
		})
	}
	for n := 0; n < 20; n++ {
		if _, err := parseResponse(make([]byte, n)); err == nil {
			t.Fatalf("accepted %d-byte header", n)
		}
	}
	for name, b := range map[string][]byte{
		"trailing bytes":            append(testResponse(nil), 0, 0, 0, 0),
		"unaligned payload":         testResponse([]byte{0, 0, 0}),
		"missing padding":           testResponse([]byte{0x80, 0x22, 0, 3, 'a', 'b', 'c'}),
		"attribute exceeds payload": testResponse([]byte{0x80, 0x22, 0, 8, 'a', 'b', 'c', 0}),
		"missing attribute value":   testResponse([]byte{0x80, 0x22, 0, 4}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseResponse(b); err == nil {
				t.Fatal("accepted malformed response")
			}
		})
	}
}

func TestParseResponsePadding(t *testing.T) {
	info, err := parseResponse(testResponse(paddedAttributes()))
	if err != nil {
		t.Fatal(err)
	}
	if info["Software"] != "abc" || info["80ff"] != "1234" {
		t.Fatalf("incorrect attribute boundaries: %+v", info)
	}
	if _, err := parseResponse(testResponse(nil)); err != nil {
		t.Fatalf("valid empty response rejected: %v", err)
	}
	attrs := append([]byte{0x80, 0x06, 0, 0}, paddedAttributes()...)
	if _, err := parseResponse(testResponse(attrs)); err != nil {
		t.Fatalf("zero-length attribute rejected: %v", err)
	}
}

func TestUDPDetectionValidatesMessageLength(t *testing.T) {
	cases := []struct {
		name          string
		mutate        func([]byte) []byte
		wantDetection bool
	}{
		{"empty response", func(b []byte) []byte { return b }, true},
		{"padded attributes", func(b []byte) []byte {
			b = append(b, paddedAttributes()...)
			binary.BigEndian.PutUint16(b[2:], uint16(len(b)-20))
			return b
		}, true},
		{"trailing bytes", func(b []byte) []byte { return append(b, 0, 0, 0, 0) }, false},
		{"wrong transaction", func(b []byte) []byte { b[8] ^= 1; return b }, false},
		{"wrong cookie", func(b []byte) []byte { b[4] ^= 1; return b }, false},
		{"wrong type", func(b []byte) []byte { b[0] = 0; return b }, false},
	}
	for length := 4; length <= 40; length += 4 {
		cases = append(cases, struct {
			name          string
			mutate        func([]byte) []byte
			wantDetection bool
		}{
			fmt.Sprintf("missing-payload-%d", length), func(b []byte) []byte { binary.BigEndian.PutUint16(b[2:], uint16(length)); return b }, false,
		})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = server.Close() }()
			done := make(chan error, 1)
			go func() {
				_ = server.SetDeadline(time.Now().Add(3 * time.Second))
				request := make([]byte, 4096)
				n, addr, err := server.ReadFrom(request)
				if err != nil {
					done <- err
					return
				}
				if n < 20 {
					done <- fmt.Errorf("short STUN request")
					return
				}
				response := testResponse(nil)
				copy(response[8:20], request[8:20])
				_, err = server.WriteTo(tc.mutate(response), addr)
				done <- err
			}()
			result, err := (&Plugin{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), server.LocalAddr().(*net.UDPAddr).Port, "stun.test", 2)
			if err != nil {
				t.Fatal(err)
			}
			if (result != nil) != tc.wantDetection {
				t.Fatalf("result=%+v; want detection=%v", result, tc.wantDetection)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func FuzzParseResponse(f *testing.F) {
	f.Add(testResponse(nil))
	f.Add(testResponse(paddedAttributes()))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, response []byte) { _, _ = parseResponse(response) })
}
