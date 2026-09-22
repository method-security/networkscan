// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package telnet

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceTelnet struct {
	ServerData string `json:"serverData"`
}

func (ServiceTelnet) Type() common.ProtocolType { return common.ProtocolTypeTelnet }
