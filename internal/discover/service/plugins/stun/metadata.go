// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package stun

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceStun struct {
	Info string `json:"info"`
}

func (ServiceStun) Type() common.ProtocolType { return common.ProtocolTypeStun }
