// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package linuxrpc

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type RPCB struct {
	Program  int    `json:"program"`
	Version  int    `json:"version"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Owner    string `json:"owner"`
}

type ServiceRPC struct {
	Entries []RPCB `json:"entries"`
}

func (ServiceRPC) Type() common.ProtocolType { return common.ProtocolTypeRpc }
