package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
)

func pcomTestReply(data string) []byte {
	s := "00ID" + data
	var checksum byte
	for i := range s {
		checksum += s[i]
	}
	return []byte(fmt.Sprintf("/A%s%02X\r", s, checksum))
}

func TestPcomIDValidation(t *testing.T) {
	valid := []byte("/A00IDR1  B30000E5\r") // Preserve padding in the controller identity.
	if err := validatePcomID(valid); err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{pcomTestReply("LAB-PLC"), pcomTestReply("R1 B30000")} {
		if err := validatePcomID(b); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string][]byte{
		"captured-binary": {0, 0x5b, 4, 0x38, 0xc0, 0xa8, 0x4e, 0xb3},
		"zero-prefix":     {0, 0, 1, 2}, "0209-prefix": {2, 9, 0, 0, 0, 0},
		"81-marker": {1, 2, 3, 4, 0x81, 0}, "bare-answer": []byte("/Agarbage\r"),
		"echo": []byte("/00IDED\r"), "http": []byte("HTTP/1.1 200 OK\r\n"),
		"empty-id": pcomTestReply(""), "blank-id": pcomTestReply("   "),
		"control": pcomTestReply("PLC\x00"), "non-ascii": pcomTestReply("PLC\xff"),
		"wrong-unit":    []byte("/A01IDR1 B30000E6\r"),
		"wrong-command": []byte("/A00IER1 B30000E6\r"),
	}
	for i := range valid {
		cases[fmt.Sprintf("truncated-%d", i)] = valid[:i]
		b := bytes.Clone(valid)
		b[i] ^= 1
		cases[fmt.Sprintf("mutated-%d", i)] = b
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validatePcomID(b); err == nil {
				t.Fatalf("accepted %q", b)
			}
		})
	}
}

func TestPcomEthernetFraming(t *testing.T) {
	body := []byte("/A00IDR1  B30000E5\r")
	header := []byte{0x34, 0x12, 101, 0, byte(len(body)), 0}
	frame := append(bytes.Clone(header), body...)
	if _, err := readPcomID(bytes.NewReader(frame), header, true); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(frame); n++ {
		if _, err := readPcomID(bytes.NewReader(frame[:n]), header, true); err == nil {
			t.Fatalf("accepted frame truncated to %d", n)
		}
	}
	for i := 0; i < 6; i++ {
		b := bytes.Clone(frame)
		b[i] ^= 0x80
		if _, err := readPcomID(bytes.NewReader(b), header, true); err == nil {
			t.Fatalf("accepted invalid header byte %d", i)
		}
	}
	for _, n := range []uint16{0, 9, 1025, 65535} {
		b := bytes.Clone(frame)
		binary.LittleEndian.PutUint16(b[4:], n)
		if _, err := readPcomID(bytes.NewReader(b), header, true); err == nil {
			t.Fatalf("accepted length %d", n)
		}
	}
	if _, err := readPcomID(bytes.NewReader(bytes.Repeat([]byte{'A'}, 2048)), nil, false); err == nil {
		t.Fatal("accepted unterminated raw reply")
	}
}

func pcomTestServer(t *testing.T, rawOnly, stall bool, reply []byte) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	t.Cleanup(func() { _ = ln.Close(); <-done; wg.Wait() })
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				first := make([]byte, 6)
				if _, err := io.ReadFull(c, first); err != nil {
					return
				}
				framed := !bytes.Equal(first, []byte("/00IDE"))
				request := make([]byte, 2)
				if framed {
					if first[2] != 101 || first[3] != 0 || binary.LittleEndian.Uint16(first[4:]) != 8 {
						t.Errorf("bad Ethernet request: %x", first)
						return
					}
					request = make([]byte, 8)
				}
				if _, err := io.ReadFull(c, request); err != nil {
					return
				}
				if !framed {
					request = append(first, request...)
				}
				if string(request) != "/00IDED\r" {
					t.Errorf("bad Get ID request: %q", request)
					return
				}
				if stall || (rawOnly && framed) {
					_, _ = io.Copy(io.Discard, c)
					return
				}
				out := bytes.Clone(reply)
				if framed {
					binary.LittleEndian.PutUint16(first[4:], uint16(len(out)))
					out = append(first, out...)
				}
				for _, b := range out {
					if _, err := c.Write([]byte{b}); err != nil {
						return
					}
					time.Sleep(time.Millisecond)
				}
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestPcomDetection(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			port := pcomTestServer(t, raw, false, []byte("/A00IDR1  B30000E5\r"))
			start := time.Now()
			s, err := (PcomFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "plc.local", 1)
			if err != nil || s == nil {
				t.Fatalf("result=%v err=%v", s, err)
			}
			if s.Protocol != common.ProtocolTypePcom || s.Transport != common.TransportTypeTcp || s.Host != "plc.local" || s.Ip != "127.0.0.1" || s.Port != port || s.Metadata != nil || s.Version != nil {
				t.Fatalf("bad details: %#v", s)
			}
			if time.Since(start) > time.Second {
				t.Fatal("fallback exceeded plugin budget")
			}
		})
	}
	for _, reply := range [][]byte{{0, 0x5b, 4, 0x38, 0xc0, 0xa8, 0x4e, 0xb3}, []byte("/Agarbage\r"), []byte("/A00IDR1 B3000000\r")} {
		port := pcomTestServer(t, false, false, reply)
		s, err := (PcomFingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 1)
		if s != nil || err == nil {
			t.Fatalf("accepted invalid response: %v %v", s, err)
		}
	}
}

func TestPcomDeadline(t *testing.T) {
	for _, timeout := range []int{1, -1} {
		t.Run(fmt.Sprint(timeout), func(t *testing.T) {
			port := pcomTestServer(t, false, true, nil)
			ctx := context.Background()
			if timeout < 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			start := time.Now()
			s, err := (PcomFingerprinter{}).Detect(ctx, net.ParseIP("127.0.0.1"), port, "localhost", timeout)
			if s != nil || err == nil || time.Since(start) > 1500*time.Millisecond {
				t.Fatalf("silent server: result=%v err=%v elapsed=%s", s, err, time.Since(start))
			}
		})
	}
}
