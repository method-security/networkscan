// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package pinecone

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServicePinecone struct {
	CPEs       []string `json:"cpes,omitempty"`
	APIVersion string   `json:"apiVersion,omitempty"`
}

func (ServicePinecone) Type() common.ProtocolType { return common.ProtocolTypePinecone }
