// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package pop3

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServicePOP3 struct {
	Banner string `json:"banner"`
}

func (ServicePOP3) Type() common.ProtocolType { return common.ProtocolTypePop3 }

type ServicePOP3S struct {
	Banner string `json:"banner"`
}

func (ServicePOP3S) Type() common.ProtocolType { return common.ProtocolTypePop3S }
