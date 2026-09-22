// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package chromadb

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceChromaDB struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (ServiceChromaDB) Type() common.ProtocolType { return common.ProtocolTypeChromadb }
