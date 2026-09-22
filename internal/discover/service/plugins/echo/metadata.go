// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package echo

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceEcho struct{}

func (ServiceEcho) Type() common.ProtocolType { return common.ProtocolTypeEcho }
