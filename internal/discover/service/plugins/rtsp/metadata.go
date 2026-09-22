// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package rtsp

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceRtsp struct {
	ServerInfo string `json:"serverInfo"`
}

func (ServiceRtsp) Type() common.ProtocolType { return common.ProtocolTypeRtsp }
