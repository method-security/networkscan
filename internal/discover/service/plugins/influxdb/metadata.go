// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package influxdb

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceInfluxDB struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (ServiceInfluxDB) Type() common.ProtocolType { return common.ProtocolTypeInfluxdb }
