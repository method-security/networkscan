package rdp

import (
	"encoding/binary"
	"testing"
)

func testChallenge() []byte {
	encode := func(s string) []byte {
		var b []byte
		for _, c := range []byte(s) {
			b = append(b, c, 0)
		}
		return b
	}
	name := encode("TARGET")
	var pairs []byte
	for i, value := range []string{"SERVER", "DOMAIN", "server.example.test", "example.test", "forest.test"} {
		b := encode(value)
		pairs = binary.LittleEndian.AppendUint16(pairs, uint16(i+1))
		pairs = binary.LittleEndian.AppendUint16(pairs, uint16(len(b)))
		pairs = append(pairs, b...)
	}
	pairs = append(pairs, 0, 0, 0, 0)
	b := make([]byte, 56)
	copy(b, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:], 2)
	binary.LittleEndian.PutUint16(b[12:], uint16(len(name)))
	binary.LittleEndian.PutUint32(b[16:], 56)
	binary.LittleEndian.PutUint16(b[40:], uint16(len(pairs)))
	binary.LittleEndian.PutUint32(b[44:], uint32(56+len(name)))
	b[48] = 10
	binary.LittleEndian.PutUint16(b[50:], 19045)
	b[55] = 15
	return append(append(b, name...), pairs...)
}

func TestRDPAuthMetadata(t *testing.T) {
	b := append([]byte{0x30, 0x82, 0, 0}, testChallenge()...)
	info, detected, err := parseRDPAuth(b)
	if err != nil || !detected || info == nil {
		t.Fatalf("result=%+v detected=%v err=%v", info, detected, err)
	}
	if info.TargetName != "TARGET" || info.NetBIOSComputerName != "SERVER" || info.NetBIOSDomainName != "DOMAIN" || info.DNSComputerName != "server.example.test" || info.DNSDomainName != "example.test" || info.ForestName != "forest.test" || info.OSVersion != "10.0.19045" {
		t.Fatalf("missing NTLM metadata: %+v", info)
	}
}

func TestRDPAuthMalformedBuffers(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"target name offset": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[16:], 0xffffffff); return b },
		"target name length": func(b []byte) []byte { binary.LittleEndian.PutUint16(b[12:], 0xffff); return b },
		"target info offset": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[44:], 0xffffffff); return b },
		"target info length": func(b []byte) []byte { binary.LittleEndian.PutUint16(b[40:], 0xffff); return b },
		"short AV header":    func(b []byte) []byte { binary.LittleEndian.PutUint16(b[40:], 1); return b },
		"short AV value": func(b []byte) []byte {
			offset := binary.LittleEndian.Uint32(b[44:])
			binary.LittleEndian.PutUint16(b[offset+2:], 0xffff)
			return b
		},
		"unknown short AV value": func(b []byte) []byte {
			offset := binary.LittleEndian.Uint32(b[44:])
			binary.LittleEndian.PutUint16(b[offset:], 99)
			binary.LittleEndian.PutUint16(b[offset+2:], 0xffff)
			return b
		},
		"AV exceeds declared region": func(b []byte) []byte { binary.LittleEndian.PutUint16(b[40:], 4); return b },
		"missing terminator": func(b []byte) []byte {
			binary.LittleEndian.PutUint16(b[40:], binary.LittleEndian.Uint16(b[40:])-4)
			return b[:len(b)-4]
		},
		"nonempty terminator": func(b []byte) []byte {
			binary.LittleEndian.PutUint16(b[len(b)-2:], 1)
			binary.LittleEndian.PutUint16(b[40:], binary.LittleEndian.Uint16(b[40:])+1)
			return append(b, 0)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			info, detected, err := parseRDPAuth(mutate(testChallenge()))
			if err == nil || detected || info != nil {
				t.Fatalf("accepted malformed challenge: %+v %v %v", info, detected, err)
			}
		})
	}
	b := testChallenge()
	for n := 0; n < len(b); n++ {
		if info, detected, _ := parseRDPAuth(b[:n]); detected || info != nil {
			t.Fatalf("accepted truncated challenge length %d", n)
		}
	}
}

func FuzzRDPAuth(f *testing.F) {
	f.Add(testChallenge())
	f.Add([]byte("NTLMSSP\x00"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _ = parseRDPAuth(b) })
}
