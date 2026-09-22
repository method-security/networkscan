// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package modbus

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceModbus struct{}

func (ServiceModbus) Type() common.ProtocolType { return common.ProtocolTypeModbus }
