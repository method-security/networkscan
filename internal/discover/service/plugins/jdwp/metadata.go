// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package jdwp

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceJDWP struct {
	Description string `json:"description"`
	JdwpMajor   int32  `json:"jdwpMajor"`
	JdwpMinor   int32  `json:"jdwpMinor"`
	VMVersion   string `json:"VMVersion"`
	VMName      string `json:"VMName"`
}

func (ServiceJDWP) Type() common.ProtocolType { return common.ProtocolTypeJdwp }
