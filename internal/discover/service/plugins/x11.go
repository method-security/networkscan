// Package plugins provides X11 service fingerprinting
package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type X11Fingerprinter struct{}

func (X11Fingerprinter) Name() string { return "x11" }

func (X11Fingerprinter) DefaultPorts() []int {
	// X11 typically runs on ports 6000-6063 (for displays :0 to :63)
	ports := make([]int, 64)
	for i := 0; i < 64; i++ {
		ports[i] = 6000 + i
	}
	return ports
}

func (X11Fingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := helpers.Dial(ctx, "tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set read/write deadline
	if err := helpers.SetDeadline(conn, timeout); err != nil {
		return nil, err
	}

	// X11 connection setup message
	// Format: byte-order + pad + major-version + minor-version + auth-proto-name-len + auth-proto-data-len + pad
	connectionSetup := []byte{
		0x6c,       // Byte order: 'l' for little-endian (0x42 'B' for big-endian)
		0x00,       // Pad
		0x0b, 0x00, // Protocol major version (11)
		0x00, 0x00, // Protocol minor version (0)
		0x00, 0x00, // Authorization protocol name length
		0x00, 0x00, // Authorization protocol data length
		0x00, 0x00, // Pad
	}

	// Send connection setup
	if _, err := conn.Write(connectionSetup); err != nil {
		return nil, err
	}

	metadata, err := readX11Setup(conn)
	if err != nil {
		return nil, err
	}

	return &discoverfern.ServiceDetails{
		Host: host, Ip: ip.String(), Port: port,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeX11,
		Version:   metadata.Version,
		Metadata:  &discoverfern.ServiceMetadata{X11: metadata},
	}, nil
}

// Connection setup encoding: https://www.x.org/releases/X11R7.7/doc/xproto/x11protocol.html
func readX11Setup(r io.Reader) (*protocol.X11ServerInfo, error) {
	var header [8]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	status := header[0]
	if status > 2 {
		return nil, fmt.Errorf("invalid X11 response status: %d", status)
	}
	// CARD16 units bound allocation to 262140 bytes, including authentication data.
	bodyLen := int(binary.LittleEndian.Uint16(header[6:8])) * 4
	authRequired := status != 1
	metadata := &protocol.X11ServerInfo{AuthRequired: &authRequired}
	if status != 2 {
		major := int(binary.LittleEndian.Uint16(header[2:4]))
		minor := int(binary.LittleEndian.Uint16(header[4:6]))
		if major != 11 || minor != 0 {
			return nil, fmt.Errorf("invalid X11 setup version: %d.%d", major, minor)
		}
		version := fmt.Sprintf("X11R%d.%d", major, minor)
		metadata.ProtocolMajor, metadata.ProtocolMinor, metadata.Version = &major, &minor, &version
	}
	if status == 0 && bodyLen != (int(header[1])+3)&^3 {
		return nil, fmt.Errorf("invalid X11 failure reason length")
	}
	if status == 1 && bodyLen < 32 {
		return nil, fmt.Errorf("short X11 success body")
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	if status != 1 {
		return metadata, nil
	}
	vendorLen := int(binary.LittleEndian.Uint16(body[16:18]))
	offset := 32 + (vendorLen+3)&^3 + 8*int(body[21])
	if offset > len(body) {
		return nil, fmt.Errorf("invalid X11 vendor or pixmap formats length")
	}
	for screen := 0; screen < int(body[20]); screen++ {
		if len(body)-offset < 40 {
			return nil, fmt.Errorf("short X11 screen")
		}
		depths := int(body[offset+39])
		offset += 40
		for depth := 0; depth < depths; depth++ {
			if len(body)-offset < 8 {
				return nil, fmt.Errorf("short X11 depth")
			}
			visuals := int(binary.LittleEndian.Uint16(body[offset+2 : offset+4]))
			offset += 8
			if visuals > (len(body)-offset)/24 {
				return nil, fmt.Errorf("short X11 visuals")
			}
			offset += 24 * visuals
		}
	}
	if offset != len(body) {
		return nil, fmt.Errorf("unexpected X11 setup data")
	}
	release := int(binary.LittleEndian.Uint32(body[:4]))
	metadata.ReleaseNumber = &release
	if vendorLen > 0 {
		vendor := string(body[32 : 32+vendorLen])
		metadata.Vendor = &vendor
	}
	return metadata, nil
}
