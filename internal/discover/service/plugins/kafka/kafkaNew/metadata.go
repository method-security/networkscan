// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package kafkanew

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceKafka struct{}

func (ServiceKafka) Type() common.ProtocolType { return common.ProtocolTypeKafka }
