// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package snpp

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceSNPP struct {
	Banner string `json:"banner"`
}

func (ServiceSNPP) Type() common.ProtocolType { return common.ProtocolTypeSnpp }
