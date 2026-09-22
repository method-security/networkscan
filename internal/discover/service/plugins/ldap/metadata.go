// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package ldap

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceLDAP struct{}

func (ServiceLDAP) Type() common.ProtocolType { return common.ProtocolTypeLdap }

type ServiceLDAPS struct{}

func (ServiceLDAPS) Type() common.ProtocolType { return common.ProtocolTypeLdaps }
