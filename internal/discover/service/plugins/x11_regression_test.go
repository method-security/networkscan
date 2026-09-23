package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
)

func x11RegressionFrame(status byte, body []byte) []byte {
	b := make([]byte, 8, 8+len(body))
	b[0], b[2] = status, 11
	binary.LittleEndian.PutUint16(b[6:], uint16(len(body)/4))
	return append(b, body...)
}

func x11RegressionSuccess() []byte {
	body := make([]byte, 32)
	binary.LittleEndian.PutUint32(body, 12345)
	binary.LittleEndian.PutUint32(body[4:], 0x200000)
	binary.LittleEndian.PutUint32(body[8:], 0x1fffff)
	binary.LittleEndian.PutUint16(body[16:], 7)
	binary.LittleEndian.PutUint16(body[18:], 65535)
	body[20], body[21] = 2, 1
	body[24], body[25], body[26], body[27] = 32, 32, 8, 255
	body = append(body, []byte("Lab X11\x00")...)
	body = append(body, 24, 32, 32, 0, 0, 0, 0, 0)
	for screen := 0; screen < 2; screen++ {
		s := make([]byte, 40)
		binary.LittleEndian.PutUint32(s, uint32(screen+1))
		binary.LittleEndian.PutUint32(s[4:], uint32(screen+3))
		binary.LittleEndian.PutUint16(s[20:], 800)
		binary.LittleEndian.PutUint16(s[22:], 600)
		binary.LittleEndian.PutUint32(s[32:], uint32(100+screen*24))
		s[38], s[39] = 24, 2
		body = append(body, s...)
		body = append(body, 24, 0, 24, 0, 0, 0, 0, 0)
		for visual := 0; visual < 24; visual++ {
			v := make([]byte, 24)
			binary.LittleEndian.PutUint32(v, uint32(100+screen*24+visual))
			v[4], v[5] = 4, 8
			binary.LittleEndian.PutUint16(v[6:], 256)
			binary.LittleEndian.PutUint32(v[8:], 0xff0000)
			binary.LittleEndian.PutUint32(v[12:], 0xff00)
			binary.LittleEndian.PutUint32(v[16:], 0xff)
			body = append(body, v...)
		}
		// Pixmap-only depth has no visuals.
		body = append(body, 1, 0, 0, 0, 0, 0, 0, 0)
	}
	return x11RegressionFrame(1, body)
}

func x11RegressionFailure() []byte {
	b := x11RegressionFrame(0, []byte("Denied!\x00"))
	b[1] = 7
	return b
}

func x11RegressionAuth() []byte {
	b := x11RegressionFrame(2, []byte("Authenticate"))
	// All five bytes are unused, including the apparent version fields.
	copy(b[1:6], []byte{255, 4, 56, 192, 168})
	return b
}

func x11RegressionServer(t *testing.T, reply []byte, fragmented, stall bool) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { _ = ln.Close(); <-done })
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		request := make([]byte, 12)
		if _, err := io.ReadFull(c, request); err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(request, []byte{'l', 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
			t.Errorf("unexpected setup request: %x", request)
			return
		}
		for len(reply) > 0 {
			n := len(reply)
			if fragmented {
				n = min(n, 3)
			}
			if _, err := c.Write(reply[:n]); err != nil {
				return // Malformed headers may be rejected before the body is sent.
			}
			reply = reply[n:]
			if fragmented {
				time.Sleep(time.Millisecond)
			}
		}
		if stall {
			_, _ = io.Copy(io.Discard, c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestX11RegressionSetup(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply []byte
	}{
		{"success", x11RegressionSuccess()},
		{"failure", x11RegressionFailure()},
		{"authenticate", x11RegressionAuth()},
		{"empty-failure", x11RegressionFrame(0, nil)},
		{"empty-authenticate", x11RegressionFrame(2, nil)},
		{"maximum-authenticate", x11RegressionFrame(2, make([]byte, 65535*4))},
	} {
		for _, fragmented := range []bool{false, true} {
			if tc.name == "maximum-authenticate" && fragmented {
				continue
			}
			t.Run(fmt.Sprintf("%s/fragmented=%t", tc.name, fragmented), func(t *testing.T) {
				port := x11RegressionServer(t, tc.reply, fragmented, true)
				result, err := (X11Fingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
				if err != nil || result == nil {
					t.Fatalf("result=%v err=%v", result, err)
				}
				if result.Host != "localhost" || result.Ip != "127.0.0.1" || result.Port != port || result.Protocol != common.ProtocolTypeX11 || result.Transport != common.TransportTypeTcp {
					t.Fatalf("bad service details: %#v", result)
				}
				m := result.Metadata.X11
				if m.AuthRequired == nil || *m.AuthRequired != (tc.reply[0] != 1) {
					t.Fatalf("bad authentication metadata: %#v", m)
				}
				if tc.reply[0] == 2 {
					if m.Version != nil || m.ProtocolMajor != nil || m.ProtocolMinor != nil || result.Version != nil {
						t.Fatal("unused authentication bytes became version metadata")
					}
				} else if m.ProtocolMajor == nil || *m.ProtocolMajor != 11 || m.ProtocolMinor == nil || *m.ProtocolMinor != 0 || m.Version == nil || *m.Version != "X11R11.0" || result.Version == nil || *result.Version != *m.Version {
					t.Fatalf("bad version metadata: %#v", m)
				}
				if tc.reply[0] == 1 {
					if m.Vendor == nil || *m.Vendor != "Lab X11" || m.ReleaseNumber == nil || *m.ReleaseNumber != 12345 {
						t.Fatalf("lost server metadata: %#v", m)
					}
				} else if m.Vendor != nil || m.ReleaseNumber != nil {
					t.Fatal("fabricated success metadata")
				}
			})
		}
	}
}

func TestX11RegressionMalformed(t *testing.T) {
	captured, err := hex.DecodeString("005b0438c0a84eb3")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{"captured": captured, "short-success": x11RegressionFrame(1, nil)}
	for name, change := range map[string]func([]byte){
		"status":         func(b []byte) { b[0] = 3 },
		"major":          func(b []byte) { b[2] = 12 },
		"minor":          func(b []byte) { b[4] = 1 },
		"vendor":         func(b []byte) { binary.LittleEndian.PutUint16(b[24:], 65535) },
		"formats":        func(b []byte) { b[29] = 255 },
		"screens":        func(b []byte) { b[28]++ },
		"depths":         func(b []byte) { b[95] = 255 },
		"visuals":        func(b []byte) { binary.LittleEndian.PutUint16(b[98:], 65535) },
		"unclaimed-data": func(b []byte) { b[28] = 0 },
	} {
		b := x11RegressionSuccess()
		change(b)
		cases[name] = b
	}
	for _, n := range []int{0, 4, 12, 256} {
		b := x11RegressionFailure()
		binary.LittleEndian.PutUint16(b[6:], uint16(n/4))
		cases[fmt.Sprintf("failure-length-%d", n)] = b
	}
	// Advertised frames ending inside each variable structure.
	for _, n := range []int{36, 44, 52, 92, 100, 108} {
		b := x11RegressionSuccess()[:n]
		binary.LittleEndian.PutUint16(b[6:], uint16((n-8)/4))
		cases[fmt.Sprintf("structure-length-%d", n)] = b
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			port := x11RegressionServer(t, reply, false, false)
			result, err := (X11Fingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 1)
			if result != nil || err == nil {
				t.Fatalf("accepted malformed frame: result=%v err=%v", result, err)
			}
		})
	}
}

func TestX11RegressionTruncated(t *testing.T) {
	for _, reply := range [][]byte{x11RegressionSuccess(), x11RegressionFailure(), x11RegressionAuth()} {
		for n := 0; n < len(reply); n++ {
			if _, err := readX11Setup(bytes.NewReader(reply[:n])); err == nil {
				t.Fatalf("accepted status %d truncated to %d", reply[0], n)
			}
		}
		t.Run(fmt.Sprintf("loopback-status-%d", reply[0]), func(t *testing.T) {
			port := x11RegressionServer(t, reply[:len(reply)-1], true, false)
			result, err := (X11Fingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 2)
			if result != nil || err == nil {
				t.Fatal("accepted truncated reply")
			}
		})
	}
}

func TestX11RegressionDeadline(t *testing.T) {
	for _, reply := range [][]byte{nil, x11RegressionSuccess()[:7], x11RegressionSuccess()[:40], x11RegressionFailure()[:8], x11RegressionAuth()[:8]} {
		t.Run(fmt.Sprintf("partial-%x", reply), func(t *testing.T) {
			port := x11RegressionServer(t, reply, false, true)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			result, err := (X11Fingerprinter{}).Detect(ctx, net.ParseIP("127.0.0.1"), port, "localhost", 2)
			if result != nil || err == nil || time.Since(start) > time.Second {
				t.Fatalf("deadline result=%v err=%v elapsed=%s", result, err, time.Since(start))
			}
		})
	}
	t.Run("probe-timeout", func(t *testing.T) {
		port := x11RegressionServer(t, x11RegressionAuth()[:8], false, true)
		start := time.Now()
		result, err := (X11Fingerprinter{}).Detect(context.Background(), net.ParseIP("127.0.0.1"), port, "localhost", 1)
		if result != nil || err == nil || time.Since(start) > 2*time.Second {
			t.Fatalf("timeout result=%v err=%v", result, err)
		}
	})
}
