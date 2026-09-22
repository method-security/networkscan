// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package rdp

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceRDP struct {
	OSFingerprint       string `json:"fingerprint,omitempty"`
	OSVersion           string `json:"osVersion,omitempty"`
	TargetName          string `json:"targetName,omitempty"`
	NetBIOSComputerName string `json:"netBIOSComputerName,omitempty"`
	NetBIOSDomainName   string `json:"netBIOSDomainName,omitempty"`
	DNSComputerName     string `json:"dnsComputerName,omitempty"`
	DNSDomainName       string `json:"dnsDomainName,omitempty"`
	ForestName          string `json:"forestName,omitempty"`
}

func (ServiceRDP) Type() common.ProtocolType { return common.ProtocolTypeRdp }
