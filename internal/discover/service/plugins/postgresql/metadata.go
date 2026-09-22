// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package postgres

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServicePostgreSQL struct {
	AuthRequired bool     `json:"authRequired"`
	CPEs         []string `json:"cpes,omitempty"`
}

func (ServicePostgreSQL) Type() common.ProtocolType { return common.ProtocolTypePostgresql }
