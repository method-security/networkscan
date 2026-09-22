// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package mqtt5

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceMQTT struct{}

func (ServiceMQTT) Type() common.ProtocolType { return common.ProtocolTypeMqtt5 }
