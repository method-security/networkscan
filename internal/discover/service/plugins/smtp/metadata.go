// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package smtp

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceSMTP struct {
	Banner      string   `json:"banner"`
	AuthMethods []string `json:"auth_methods"`
}

func (ServiceSMTP) Type() common.ProtocolType { return common.ProtocolTypeSmtp }

type ServiceSMTPS struct {
	Banner      string   `json:"banner"`
	AuthMethods []string `json:"authMethods"`
}

func (ServiceSMTPS) Type() common.ProtocolType { return common.ProtocolTypeSmtps }
