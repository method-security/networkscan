// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package redis

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceRedis struct {
	AuthRequired bool     `json:"authRequired"`
	CPEs         []string `json:"cpes,omitempty"`
}

func (ServiceRedis) Type() common.ProtocolType { return common.ProtocolTypeRedis }
