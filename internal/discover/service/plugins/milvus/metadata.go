// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package milvus

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceMilvus struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (ServiceMilvus) Type() common.ProtocolType { return common.ProtocolTypeMilvus }

type ServiceMilvusMetrics struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (ServiceMilvusMetrics) Type() common.ProtocolType { return common.ProtocolTypeMilvus }
