// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package db2

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceDB2 struct {
	ServerName string   `json:"serverName,omitempty"`
	CPEs       []string `json:"cpes,omitempty"`
}

func (ServiceDB2) Type() common.ProtocolType { return common.ProtocolTypeDb2 }
