package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

func udpReplyFixture(t *testing.T, reply func([]byte) []byte) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		n, addr, err := c.ReadFromUDP(b)
		if err == nil {
			_, _ = c.WriteToUDP(reply(b[:n]), addr)
		}
	}()
	t.Cleanup(func() { _ = c.Close(); <-done })
	return c.LocalAddr().(*net.UDPAddr).Port
}

type udpReplyDetector interface {
	Detect(context.Context, net.IP, int, string, int) (*discoverfern.ServiceDetails, error)
}

func checkUDPReply(t *testing.T, detector udpReplyDetector, port int, valid bool) *discoverfern.ServiceDetails {
	t.Helper()
	r, err := detector.Detect(context.Background(), net.IPv4(127, 0, 0, 1), port, "fixture.local", 1)
	if valid && (err != nil || r == nil) {
		t.Fatalf("valid reply rejected: %v", err)
	}
	if !valid && r != nil {
		t.Fatalf("invalid reply detected: %+v", r)
	}
	return r
}

func TestNTPReplyValidation(t *testing.T) {
	for _, name := range []string{"valid", "extension", "kod", "unsynchronized", "version-zero", "version-five", "stratum-200", "broadcast", "uncorrelated", "short", "http"} {
		t.Run(name, func(t *testing.T) {
			valid := name == "valid" || name == "extension" || name == "kod" || name == "unsynchronized"
			port := udpReplyFixture(t, func(request []byte) []byte {
				if len(request) != 48 || bytes.Equal(request[40:48], make([]byte, 8)) {
					t.Error("request needs a nonzero transmit timestamp")
				}
				b := make([]byte, 48)
				b[0], b[1] = 0x24, 2
				copy(b[24:32], request[40:48])
				copy(b[40:48], request[40:48])
				copy(b[12:16], []byte{127, 0, 0, 1})
				switch name {
				case "extension":
					b = append(b, make([]byte, 28)...)
					binary.BigEndian.PutUint16(b[50:52], 28)
				case "kod":
					b[1] = 0
					copy(b[12:16], "RATE")
				case "unsynchronized":
					b[0], b[1] = 0xe4, 16
				case "version-zero":
					b[0] = 4
				case "version-five":
					b[0] = 0x2c
				case "stratum-200":
					b[1] = 200
				case "broadcast":
					b[0] = 0x25
				case "uncorrelated":
					b[24] ^= 1
				case "short":
					b = b[:47]
				case "http":
					b = []byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
				}
				return b
			})
			r := checkUDPReply(t, NTPFingerprinter{}, port, valid)
			if valid {
				m := r.Metadata.Ntp
				if *m.Version != "4" || *m.Mode != "server" {
					t.Fatalf("missing NTP metadata: %+v", m)
				}
				if name == "kod" && (m.ReferenceId == nil || *m.ReferenceId != "RATE") {
					t.Fatal("missing KoD reference ID")
				}
			}
		})
	}
}

func TestIKEReplyValidation(t *testing.T) {
	for _, name := range []string{"notify", "vendor", "proposal", "text", "http", "spi", "version", "exchange", "request", "initiator", "message-id", "length", "empty", "short-payload", "oversize-payload", "unterminated", "trailing", "short-notify"} {
		t.Run(name, func(t *testing.T) {
			port := udpReplyFixture(t, func(request []byte) []byte {
				b := make([]byte, 36)
				copy(b[:8], request[:8])
				b[16], b[17], b[18], b[19] = 41, 0x20, 34, 0x20
				binary.BigEndian.PutUint32(b[24:28], uint32(len(b)))
				copy(b[28:], []byte{0, 0, 0, 8, 0, 0, 0, 14})
				switch name {
				case "proposal":
					b = append(b[:28], []byte{
						0, 0, 0, 20,
						0, 0, 0, 16, 1, 1, 0, 1,
						0, 0, 0, 8, 1, 0, 0, 3,
					}...)
					b[16] = 33
					b[8] = 1
					binary.BigEndian.PutUint32(b[24:28], uint32(len(b)))
				case "vendor":
					b[16] = 43
					copy(b[32:], "test")
				case "text":
					return bytes.Repeat([]byte("unrelated service "), 4)
				case "http":
					return []byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
				case "spi":
					b[0] ^= 1
				case "version":
					b[17] = 0x10
				case "exchange":
					b[18] = 35
				case "request":
					b[19] = 0
				case "initiator":
					b[19] = 0x28
				case "message-id":
					b[23] = 1
				case "length":
					b[27]++
				case "empty":
					b[16] = 0
				case "short-payload":
					b[31] = 3
				case "oversize-payload":
					b[31] = 9
				case "unterminated":
					b[28] = 41
				case "trailing":
					b[16], b[31] = 43, 4
				case "short-notify":
					b, b[27], b[31] = b[:32], 32, 4
				}
				return b
			})
			valid := name == "notify" || name == "vendor" || name == "proposal"
			r := checkUDPReply(t, IKEFingerprinter{}, port, valid)
			if valid && (*r.Metadata.Ike.Version != "IKEv2" || *r.Metadata.Ike.ExchangeType != "IKE_SA_INIT") {
				t.Fatal("missing IKE header metadata")
			}
			if name == "vendor" && (len(r.Metadata.Ike.VendorIds) != 1 || r.Metadata.Ike.VendorIds[0] != "74657374") {
				t.Fatal("missing vendor metadata")
			}
			if name == "proposal" && len(r.Metadata.Ike.EncryptionAlgorithms) != 1 {
				t.Fatal("missing selected encryption metadata")
			}
		})
	}
}

func TestIKENATTFraming(t *testing.T) {
	request := make([]byte, 28)
	copy(request[:8], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	request[17], request[18], request[19] = 0x20, 34, 8
	binary.BigEndian.PutUint32(request[24:28], uint32(len(request)))
	original := append([]byte(nil), request...)
	for _, port := range []int{500, 4500} {
		wire := frameIKERequest(request, port)
		want := request
		if port == 4500 {
			want = append([]byte{0, 0, 0, 0}, request...)
		}
		if !bytes.Equal(wire, want) || !bytes.Equal(request, original) {
			t.Fatalf("incorrect request framing on port %d", port)
		}
	}

	reply := append(append([]byte(nil), request...), 0, 0, 0, 8, 0, 0, 0, 14)
	reply[16], reply[19] = 41, 0x20
	binary.BigEndian.PutUint32(reply[24:28], uint32(len(reply)))
	for _, name := range []string{"valid", "missing-marker", "esp", "short-marker", "marker-only", "uncorrelated"} {
		t.Run(name, func(t *testing.T) {
			wire := append([]byte{0, 0, 0, 0}, reply...)
			switch name {
			case "missing-marker":
				wire = wire[4:]
			case "esp":
				wire[0] = 1
			case "short-marker":
				wire = wire[:3]
			case "marker-only":
				wire = wire[:4]
			case "uncorrelated":
				wire[4] ^= 1
			}
			parsed, header, err := validateIKEReply(wire, request, true)
			if name == "valid" {
				if err != nil || header == nil || !bytes.Equal(parsed, reply) {
					t.Fatalf("valid NAT-T reply rejected: %v", err)
				}
			} else if err == nil {
				t.Fatal("invalid NAT-T reply accepted")
			}
		})
	}
}

func TestSSDPReplyValidation(t *testing.T) {
	base := "HTTP/1.1 200 OK\r\nsT: upnp:rootdevice\r\nuSn: uuid:fixture\r\nlocation: http://127.0.0.1/device.xml\r\nserver: fixture/1\r\ncache-control: max-age=60\r\n\r\n"
	for _, name := range []string{"valid", "404", "ordinary-http", "missing-st", "missing-usn", "missing-location", "malformed", "truncated"} {
		t.Run(name, func(t *testing.T) {
			b := base
			switch name {
			case "404":
				b = strings.Replace(b, "200 OK", "404 Not Found", 1)
			case "ordinary-http":
				b = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
			case "missing-st":
				b = strings.Replace(b, "sT: upnp:rootdevice\r\n", "", 1)
			case "missing-usn":
				b = strings.Replace(b, "uSn: uuid:fixture\r\n", "", 1)
			case "missing-location":
				b = strings.Replace(b, "location: http://127.0.0.1/device.xml\r\n", "", 1)
			case "malformed":
				b = strings.Replace(b, "server:", "invalid header", 1)
			case "truncated":
				b = strings.TrimSuffix(b, "\r\n")
			}
			port := udpReplyFixture(t, func([]byte) []byte { return []byte(b) })
			r := checkUDPReply(t, SSDPFingerprinter{}, port, name == "valid")
			if r != nil {
				m := r.Metadata.Ssdp
				if *m.Status != "HTTP/1.1 200 OK" || *m.Server != "fixture/1" || *m.CacheControl != "max-age=60" || *m.ServiceType != "upnp:rootdevice" || *m.Usn != "uuid:fixture" || *m.Location != "http://127.0.0.1/device.xml" || *r.Version != "fixture/1" {
					t.Fatalf("missing SSDP metadata: %+v", m)
				}
			}
		})
	}
}
