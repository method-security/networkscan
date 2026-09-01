// Package plugins provides ARD (Apple Remote Desktop) service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type ArdFingerprinter struct{}

func (ArdFingerprinter) Name() string { return "ard" }

func (ArdFingerprinter) DefaultPorts() []int { return []int{3283, 5900} }

func (ArdFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
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

	// ARD uses VNC protocol with Apple extensions
	// VNC handshake starts with server sending RFB protocol version
	// Read server version
	versionBuf := make([]byte, 12)
	n, err := conn.Read(versionBuf)
	if err != nil {
		return nil, err
	}

	if n != 12 {
		return nil, fmt.Errorf("invalid VNC handshake length")
	}

	// Check for RFB protocol version string (e.g., "RFB 003.008\n")
	versionStr := string(versionBuf)
	if !strings.HasPrefix(versionStr, "RFB ") {
		return nil, fmt.Errorf("invalid RFB protocol header")
	}

	// Extract protocol version
	var version *string
	protocolVersion := strings.TrimSpace(strings.TrimPrefix(versionStr, "RFB "))
	version = &protocolVersion

	// Send client version (same as server)
	if _, err := conn.Write(versionBuf); err != nil {
		return nil, err
	}

	// Read security types
	securityBuf := make([]byte, 256)
	n, err = conn.Read(securityBuf)
	if err != nil {
		return nil, err
	}

	var machineName, osVersion *string

	// Check for Apple-specific security types
	// Apple Remote Desktop typically uses security type 30 (Apple Remote Desktop)
	isARD := false
	if n > 1 {
		numSecurityTypes := int(securityBuf[0])
		if numSecurityTypes > 0 && n >= numSecurityTypes+1 {
			for i := 1; i <= numSecurityTypes; i++ {
				secType := securityBuf[i]
				// Security type 30 is Apple Remote Desktop
				// Security type 35 is also used by ARD
				if secType == 30 || secType == 35 {
					isARD = true
					break
				}
			}
		}
	}

	if !isARD {
		// Not ARD, likely regular VNC
		return nil, fmt.Errorf("not Apple Remote Desktop")
	}

	// Try to get machine info by selecting ARD security type
	// Send security type selection (type 30)
	if _, err := conn.Write([]byte{30}); err == nil {
		// ARD may send additional handshake data
		infoBuf := make([]byte, 1024)
		if n, err := conn.Read(infoBuf); err == nil && n > 0 {
			// Try to extract machine name from response
			infoStr := string(infoBuf[:n])
			if idx := strings.Index(infoStr, ".local"); idx > 0 {
				// Found a hostname
				startIdx := idx
				for startIdx > 0 && infoBuf[startIdx-1] >= 32 && infoBuf[startIdx-1] <= 126 {
					startIdx--
				}
				machineNameStr := string(infoBuf[startIdx : idx+6])
				machineName = &machineNameStr
			}
		}
	}

	// Determine OS version (ARD is macOS-specific)
	osVersionStr := "macOS"
	osVersion = &osVersionStr

	metadata := &protocol.ArdServerInfo{
		Version:     version,
		MachineName: machineName,
		OsVersion:   osVersion,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeArd,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Ard: metadata},
	}

	return result, nil
}
