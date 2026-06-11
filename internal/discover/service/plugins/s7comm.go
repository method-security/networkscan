// Package plugins provides Siemens S7comm / ISO-on-TCP service fingerprinting
// on TCP/102. The fingerprinter reuses the deep S7 probe at
// internal/discover/s7 so the service-discovery stage gets the same SZL data
// (CPU type, firmware, order code, rack/slot) the standalone "discover s7"
// command surfaces.
package plugins

import (
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/s7"
)

type S7CommFingerprinter struct{}

func (S7CommFingerprinter) Name() string { return "s7comm" }

func (S7CommFingerprinter) DefaultPorts() []int { return []int{102} }

func (S7CommFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	info, _, err := s7.Probe(ctx, ip, port, s7.Options{
		Timeout:     timeout,
		TSAPVariant: s7.TSAPVariantAuto,
		// Always do SZL during fingerprint — it's read-only and lets
		// downstream processors build a typed PLC object without an
		// extra scan stage.
		SkipSZL: false,
	})
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, fmt.Errorf("not S7comm")
	}

	versionStr := s7VersionDisplay(info)
	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeS7Comm,
		Version:   &versionStr,
		Metadata:  &discoverfern.ServiceMetadata{S7Comm: info},
	}, nil
}

// s7VersionDisplay builds the ServiceDetails.Version banner string.
// Prefers firmware version; falls back to module name; defaults to a
// generic protocol label so the field is always populated.
func s7VersionDisplay(info *protocol.S7CommServerInfo) string {
	if v := info.GetFirmwareVersion(); v != nil && *v != "" {
		return *v
	}
	if m := info.GetModuleName(); m != nil && *m != "" {
		return *m
	}
	return "Siemens S7comm"
}
