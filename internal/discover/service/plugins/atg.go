// Package plugins provides ATG (Automatic Tank Gauging) service fingerprinting
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

type AtgFingerprinter struct{}

func (AtgFingerprinter) Name() string { return "atg" }

func (AtgFingerprinter) DefaultPorts() []int { return []int{10001} }

func (AtgFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
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

	// ATG systems often use ASCII-based protocols
	// Common commands: I20100 (Inventory Report), I10100 (In-Tank Leak Detection)
	// Send an inventory status request (I20100)
	atgRequest := []byte{0x01} // SOH (Start of Header)
	atgRequest = append(atgRequest, []byte("I20100")...)
	atgRequest = append(atgRequest, 0x0A) // LF (Line Feed)

	// Send inventory request
	if _, err := conn.Write(atgRequest); err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// ATG responses typically start with SOH (0x01) or ACK (0x06)
	if n < 10 {
		return nil, fmt.Errorf("response too short")
	}

	// Verify ATG response (should start with SOH or ACK)
	if response[0] != 0x01 && response[0] != 0x06 {
		return nil, fmt.Errorf("invalid ATG response header")
	}

	// Extract device information from response
	var manufacturer, model, tankID *string
	var version *string

	// Parse ASCII response
	responseStr := string(response[1:n])

	// Look for common ATG manufacturers in response
	if strings.Contains(responseStr, "VEEDER") || strings.Contains(responseStr, "VR") {
		mfg := "Veeder-Root"
		manufacturer = &mfg
	} else if strings.Contains(responseStr, "GILBARCO") {
		mfg := "Gilbarco"
		manufacturer = &mfg
	} else if strings.Contains(responseStr, "OPW") {
		mfg := "OPW"
		manufacturer = &mfg
	} else if strings.Contains(responseStr, "FRANKLIN") {
		mfg := "Franklin Fueling"
		manufacturer = &mfg
	}

	// Try to extract model information
	// ATG responses often contain model codes like "TLS-350", "TLS-450", etc.
	if idx := strings.Index(responseStr, "TLS"); idx >= 0 && idx+7 < len(responseStr) {
		modelStr := responseStr[idx : idx+7]
		model = &modelStr
	}

	// Try to extract tank ID from inventory report
	// Format varies, but often looks like "Tank 01" or "TK01"
	lines := strings.Split(responseStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Tank") || strings.Contains(line, "TK") {
			tankIDStr := strings.TrimSpace(line)
			if len(tankIDStr) > 0 && len(tankIDStr) < 50 {
				tankID = &tankIDStr
				break
			}
		}
	}

	// Set version based on manufacturer or default
	if manufacturer != nil {
		versionStr := *manufacturer + " ATG"
		version = &versionStr
	} else {
		versionStr := "ATG System"
		version = &versionStr
	}

	metadata := &protocol.AtgServerInfo{
		Version:      version,
		Manufacturer: manufacturer,
		Model:        model,
		TankId:       tankID,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeAtg,
		Version:   version,
		Metadata:  &discoverfern.ServiceMetadata{Atg: metadata},
	}

	return result, nil
}
