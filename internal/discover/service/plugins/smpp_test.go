package plugins

import (
	"encoding/binary"
	"testing"
)

func nativeSMPPFixture(request []byte) []byte {
	b := nativeBinaryWords(0, 0x80000001, 0, binary.BigEndian.Uint32(request[12:]))
	b = append(b, []byte("loopback-smsc\x00")...)
	b = append(b, 2, 0x10, 0, 1, 0x34)
	binary.BigEndian.PutUint32(b, uint32(len(b)))
	return b
}

func TestNativeBinarySMPP(t *testing.T) {
	nativeBinaryCases(t, SMPPFingerprinter{}, func(request []byte) []byte {
		if len(request) != 23 || binary.BigEndian.Uint32(request[4:]) != 1 || string(request[16:]) != "\x00\x00\x00\x34\x00\x00\x00" {
			t.Error("expected single empty-credential bind_receiver")
		}
		return nativeSMPPFixture(request)
	}, map[string]func([]byte) []byte{
		"wrong_sequence": func(b []byte) []byte { b[15] ^= 1; return b },
		"wrong_command":  func(b []byte) []byte { b[7] = 2; return b },
		"request_bit":    func(b []byte) []byte { b[4] = 0; return b },
		"oversized":      func(b []byte) []byte { binary.BigEndian.PutUint32(b, 0xffffffff); return b[:16] },
		"short_length":   func(b []byte) []byte { binary.BigEndian.PutUint32(b, 15); return b[:16] },
		"bad_tlv":        func(b []byte) []byte { b[len(b)-2] = 2; return b },
		"unterminated_system_id": func(b []byte) []byte {
			for i := 16; i < len(b); i++ {
				b[i] = 'x'
			}
			return b
		},
		"truncated": func(b []byte) []byte { return b[:len(b)-1] },
	}, map[string]string{"systemID": "loopback-smsc", "protocolVersion": "3.4", "probe": "bind_receiver"})
	for _, status := range []uint32{13, 14, 15} {
		t.Run("bind_rejection", func(t *testing.T) {
			nativeBinaryCases(t, SMPPFingerprinter{}, func(request []byte) []byte {
				return nativeBinaryWords(16, 0x80000001, status, binary.BigEndian.Uint32(request[12:]))
			}, map[string]func([]byte) []byte{}, map[string]string{"probe": "bind_receiver"})
		})
	}
}
