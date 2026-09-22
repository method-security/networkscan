package helpers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/common/ntlm"
)

type Metadata interface{ Type() common.ProtocolType }

func MetadataResult(target Endpoint, payload Metadata, tlsEnabled bool, version string, transport common.TransportType) *discover.ServiceDetails {
	if payload == nil {
		return nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil
	}
	metadata := make(map[string]string, len(fields))
	for k, v := range fields {
		metadata[k] = fmt.Sprintf("%v", v)
	}
	if osVersion := metadata["osVersion"]; osVersion != "" {
		parts := strings.Split(osVersion, ".")
		if len(parts) >= 3 {
			metadata["mappedOsVersion"] = ntlm.ParseWindowsVersion("Build " + parts[2])
		}
	}
	wireTransport := common.TransportTypeTcp
	if transport == common.TransportTypeUdp {
		wireTransport = common.TransportTypeUdp
	}
	return &discover.ServiceDetails{Host: target.Host, Ip: target.Address.Addr().String(), Port: int(target.Address.Port()), Tls: &tlsEnabled, Version: &version, Transport: wireTransport, Protocol: payload.Type(), Metadata: &discover.ServiceMetadata{Generic: &discover.GenericServiceMetadata{Metadata: metadata}}}
}
