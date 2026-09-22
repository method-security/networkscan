// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package mysql

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceMySQL struct {
	PacketType   string   `json:"packetType"`
	ErrorMessage string   `json:"errorMsg"`
	ErrorCode    int      `json:"errorCode"`
	CPEs         []string `json:"cpes,omitempty"`
}

func (ServiceMySQL) Type() common.ProtocolType { return common.ProtocolTypeMysql }
