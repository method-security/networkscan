// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package mssql

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceMSSQL struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (ServiceMSSQL) Type() common.ProtocolType { return common.ProtocolTypeMssql }
