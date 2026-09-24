package plugins

import (
	"context"
	"encoding/binary"
	"hash/crc32"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

func stunTestPacket(kind uint16, attributes ...[]byte) []byte {
	packet := make([]byte, 20)
	binary.BigEndian.PutUint16(packet, kind)
	binary.BigEndian.PutUint32(packet[4:], 0x2112a442)
	copy(packet[8:], "test-message")
	for _, attribute := range attributes {
		packet = append(packet, attribute...)
	}
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)-20))
	return packet
}

func stunTestAttribute(kind uint16, value []byte) []byte {
	attribute := make([]byte, 4+((len(value)+3)&^3))
	binary.BigEndian.PutUint16(attribute, kind)
	binary.BigEndian.PutUint16(attribute[2:], uint16(len(value)))
	copy(attribute[4:], value)
	return attribute
}

func TestNativeSTUNResponses(t *testing.T) {
	transaction := []byte("test-message")
	for _, tc := range []struct {
		name       string
		packet     []byte
		key, value string
	}{
		{"empty binding", stunTestPacket(0x101), "", ""},
		{"software and padding", stunTestPacket(0x101, stunTestAttribute(0x8022, []byte("test-stun"))), "software", "test-stun"},
		{"mapped IPv4", stunTestPacket(0x101, stunTestAttribute(1, []byte{0, 1, 0x1f, 0x90, 10, 0, 0, 1})), "mappedAddress", "10.0.0.1:8080"},
		{"xor IPv4", stunTestPacket(0x101, stunTestAttribute(0x20, []byte{0, 1, 0x3e, 0x82, 0x2b, 0x12, 0xa4, 0x43})), "xorMappedAddress", "10.0.0.1:8080"},
		{"error", stunTestPacket(0x111, stunTestAttribute(9, []byte{0, 0, 4, 1})), "errorCode", "401"},
		{"unknown optional", stunTestPacket(0x101, stunTestAttribute(0xafff, []byte{1})), "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadata, err := parseSTUNBindingResponse(tc.packet, transaction)
			if err != nil {
				t.Fatal(err)
			}
			if tc.key != "" && metadata[tc.key] != tc.value {
				t.Fatalf("metadata: %v", metadata)
			}
		})
	}
	ipv6 := make([]byte, 20)
	ipv6[1] = 2
	binary.BigEndian.PutUint16(ipv6[2:], 8080)
	copy(ipv6[4:], net.ParseIP("fd00::1").To16())
	packet := stunTestPacket(0x101, stunTestAttribute(1, ipv6))
	metadata, err := parseSTUNBindingResponse(packet, transaction)
	if err != nil || metadata["mappedAddress"] != "[fd00::1]:8080" {
		t.Fatalf("IPv6: %v, %v", metadata, err)
	}
	for i := 4; i < len(ipv6); i++ {
		ipv6[i] ^= packet[i]
	}
	binary.BigEndian.PutUint16(ipv6[2:], 8080^0x2112)
	metadata, err = parseSTUNBindingResponse(stunTestPacket(0x101, stunTestAttribute(0x20, ipv6)), transaction)
	if err != nil || metadata["xorMappedAddress"] != "[fd00::1]:8080" {
		t.Fatalf("XOR IPv6: %v, %v", metadata, err)
	}
}

func TestNativeSTUNRejectsMalformed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func([]byte) []byte
	}{
		{"short header", func(p []byte) []byte { return p[:19] }},
		{"different transaction", func(p []byte) []byte { p[8] ^= 1; return p }},
		{"different cookie", func(p []byte) []byte { p[4] ^= 1; return p }},
		{"request echo", func(p []byte) []byte { p[0] = 0; return p }},
		{"wrong method", func(p []byte) []byte { p[1] = 2; return p }},
		{"reserved type bits", func(p []byte) []byte { p[0] |= 0x80; return p }},
		{"unaligned size", func(p []byte) []byte { p[3] = 1; return append(p, 0) }},
		{"oversized length", func(p []byte) []byte { p[3] = 4; return p }},
		{"trailing bytes", func(p []byte) []byte { return append(p, 0, 0, 0, 0) }},
		{"truncated attribute", func(p []byte) []byte { return stunTestPacket(0x101, []byte{0x80, 0x22, 0, 8}) }},
		{"missing padding", func(p []byte) []byte { return stunTestPacket(0x101, []byte{0x80, 0x22, 0, 1, 'x'}) }},
		{"invalid software", func(p []byte) []byte { return stunTestPacket(0x101, stunTestAttribute(0x8022, []byte{0xff})) }},
		{"oversized software", func(p []byte) []byte {
			return stunTestPacket(0x101, stunTestAttribute(0x8022, []byte(strings.Repeat("x", 128))))
		}},
		{"invalid address family", func(p []byte) []byte { return stunTestPacket(0x101, stunTestAttribute(1, []byte{0, 3, 0, 1})) }},
		{"truncated address", func(p []byte) []byte { return stunTestPacket(0x101, stunTestAttribute(1, []byte{0, 1, 0, 1})) }},
		{"missing error code", func(p []byte) []byte { return stunTestPacket(0x111) }},
		{"invalid error code", func(p []byte) []byte { return stunTestPacket(0x111, stunTestAttribute(9, []byte{0, 0, 7, 1})) }},
		{"bad fingerprint", func(p []byte) []byte { return stunTestPacket(0x101, stunTestAttribute(0x8028, []byte{0, 0, 0, 0})) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseSTUNBindingResponse(tc.modify(stunTestPacket(0x101)), []byte("test-message")); err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
}

func TestNativeSTUNFingerprint(t *testing.T) {
	packet := stunTestPacket(0x101, stunTestAttribute(0x8028, make([]byte, 4)))
	binary.BigEndian.PutUint32(packet[len(packet)-4:], crc32.ChecksumIEEE(packet[:20])^0x5354554e)
	if _, err := parseSTUNBindingResponse(packet, []byte("test-message")); err != nil {
		t.Fatal(err)
	}
	packet = append(packet, stunTestAttribute(0x8022, []byte("after"))...)
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)-20))
	if _, err := parseSTUNBindingResponse(packet, []byte("test-message")); err == nil {
		t.Fatal("fingerprint not last accepted")
	}
}

func openVPNTestReset(session []byte) []byte {
	packet := make([]byte, 26)
	packet[0] = 8 << 3
	copy(packet[1:9], "serverid")
	packet[9] = 1
	copy(packet[14:22], session)
	return packet
}

func TestNativeOpenVPNReset(t *testing.T) {
	session := []byte("clientid")
	if !validOpenVPNReset(openVPNTestReset(session), session) {
		t.Fatal("valid reset rejected")
	}
	noACK := make([]byte, 14)
	noACK[0] = 8 << 3
	copy(noACK[1:9], "serverid")
	if !validOpenVPNReset(noACK, session) {
		t.Fatal("reset without piggyback ACK rejected")
	}
	for _, tc := range []struct {
		name   string
		modify func([]byte) []byte
	}{
		{"truncated", func(p []byte) []byte { return p[:9] }},
		{"wrong opcode", func(p []byte) []byte { p[0] = 7 << 3; return p }},
		{"wrong key", func(p []byte) []byte { p[0] |= 1; return p }},
		{"wrong session", func(p []byte) []byte { p[14] ^= 1; return p }},
		{"wrong acknowledged packet", func(p []byte) []byte { p[13] = 1; return p }},
		{"wrong reset sequence", func(p []byte) []byte { p[25] = 1; return p }},
		{"truncated ACK array", func(p []byte) []byte { p[9] = 255; return p }},
		{"trailing bytes", func(p []byte) []byte { return append(p, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if validOpenVPNReset(tc.modify(openVPNTestReset(session)), session) {
				t.Fatal("malformed reset accepted")
			}
		})
	}
}

type nativeUDPDetector interface {
	Detect(context.Context, net.IP, int, string, int) (*discoverfern.ServiceDetails, error)
}

func TestNativeMissingUDPPlugins(t *testing.T) {
	for _, tc := range []struct {
		name     string
		plugin   nativeUDPDetector
		protocol common.ProtocolType
		reply    func([]byte) []byte
	}{
		{"STUN", STUNFingerprinter{}, common.ProtocolTypeStun, func(request []byte) []byte {
			response := stunTestPacket(0x101, stunTestAttribute(0x8022, []byte("local-server")))
			copy(response[8:20], request[8:20])
			return response
		}},
		{"OpenVPN", OpenVPNFingerprinter{}, common.ProtocolTypeOpenvpn, func(request []byte) []byte { return openVPNTestReset(request[1:9]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			finished := make(chan error, 1)
			go func() {
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				request := make([]byte, 128)
				n, address, err := conn.ReadFromUDP(request)
				if err == nil {
					_, err = conn.WriteToUDP(tc.reply(request[:n]), address)
				}
				finished <- err
			}()
			result, err := tc.plugin.Detect(context.Background(), net.ParseIP("127.0.0.1"), conn.LocalAddr().(*net.UDPAddr).Port, "udp.test", 2)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || result.Protocol != tc.protocol || result.Host != "udp.test" || result.Transport != common.TransportTypeUdp {
				t.Fatalf("unexpected result: %+v", result)
			}
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
		})
		t.Run(tc.name+" cancellation", func(t *testing.T) {
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			result, err := tc.plugin.Detect(ctx, net.ParseIP("127.0.0.1"), conn.LocalAddr().(*net.UDPAddr).Port, "udp.test", 30)
			if err == nil || result != nil || time.Since(start) > 2*time.Second {
				t.Fatalf("cancellation failed: %v, %+v", err, result)
			}
		})
	}
}

func FuzzNativeSTUNResponse(f *testing.F) {
	f.Add(stunTestPacket(0x101))
	f.Add([]byte("not STUN"))
	f.Fuzz(func(t *testing.T, packet []byte) { _, _ = parseSTUNBindingResponse(packet, []byte("test-message")) })
}

func FuzzNativeOpenVPNReset(f *testing.F) {
	f.Add(openVPNTestReset([]byte("clientid")))
	f.Add([]byte("not OpenVPN"))
	f.Fuzz(func(t *testing.T, packet []byte) { _ = validOpenVPNReset(packet, []byte("clientid")) })
}
