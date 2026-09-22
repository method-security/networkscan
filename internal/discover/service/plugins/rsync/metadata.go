// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package rsync

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceRsync struct{}

func (ServiceRsync) Type() common.ProtocolType { return common.ProtocolTypeRsync }
