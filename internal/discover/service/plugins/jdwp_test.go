package plugins

import (
	"encoding/binary"
	"testing"
)

func nativeJDWPFixture(request []byte) []byte {
	b := append(nativeBinaryWords(0, binary.BigEndian.Uint32(request[4:])), 0x80, 0, 0)
	b = append(b, nativeBinaryWords(7)...)
	b = append(b, "Test VM"...)
	b = append(b, nativeBinaryWords(1, 8, 4)...)
	b = append(b, "21.0"...)
	b = append(b, nativeBinaryWords(7)...)
	b = append(b, "TestJVM"...)
	binary.BigEndian.PutUint32(b, uint32(len(b)))
	return b
}

func TestNativeBinaryJDWP(t *testing.T) {
	nativeBinaryCases(t, JDWPFingerprinter{}, func(request []byte) []byte {
		if len(request) != 11 || string(request[8:]) != "\x00\x01\x01" {
			t.Error("expected VM Version command")
		}
		return nativeJDWPFixture(request)
	}, map[string]func([]byte) []byte{
		"wrong_id":     func(b []byte) []byte { b[7] ^= 1; return b },
		"wrong_flags":  func(b []byte) []byte { b[8] = 0; return b },
		"error_reply":  func(b []byte) []byte { b[10] = 99; return b },
		"oversized":    func(b []byte) []byte { binary.BigEndian.PutUint32(b, 0xffffffff); return b[:11] },
		"short_length": func(b []byte) []byte { binary.BigEndian.PutUint32(b, 10); return b[:11] },
		"bad_string":   func(b []byte) []byte { binary.BigEndian.PutUint32(b[11:], 0xffffffff); return b },
		"invalid_utf8": func(b []byte) []byte { b[15] = 0xff; return b },
		"trailing":     func(b []byte) []byte { b = append(b, 0); binary.BigEndian.PutUint32(b, uint32(len(b))); return b },
		"truncated":    func(b []byte) []byte { return b[:len(b)-1] },
	}, map[string]string{"description": "Test VM", "jdwpMajor": "1", "jdwpMinor": "8", "VMVersion": "21.0", "VMName": "TestJVM"})
}

func TestNativeBinaryJDWPEvent(t *testing.T) {
	nativeBinaryCases(t, JDWPFingerprinter{}, func(request []byte) []byte {
		// Composite VMStart: suspend policy, count, event kind, request ID, thread ID.
		event := append(nativeBinaryWords(29, 9), 0, 64, 100, 0)
		event = append(event, nativeBinaryWords(1)...)
		event = append(event, 90)
		event = append(event, nativeBinaryWords(0, 0, 1)...)
		return append(event, nativeJDWPFixture(request)...)
	}, map[string]func([]byte) []byte{
		"unrelated_command": func(b []byte) []byte { b[9] = 1; return b },
		"invalid_suspend":   func(b []byte) []byte { b[11] = 3; return b },
	}, map[string]string{"VMName": "TestJVM"})
}
