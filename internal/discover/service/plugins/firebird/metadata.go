// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package firebird

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceFirebird struct {
	ProtocolVersion int32    `json:"protocol_version,omitempty"`
	CPEs            []string `json:"cpes,omitempty"`
}

func (ServiceFirebird) Type() common.ProtocolType { return common.ProtocolTypeFirebird }
