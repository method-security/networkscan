// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package sybase

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceSybase struct {
	CPEs    []string `json:"cpes,omitempty"`
	Version string   `json:"version,omitempty"`
}

func (ServiceSybase) Type() common.ProtocolType { return common.ProtocolTypeSybase }
