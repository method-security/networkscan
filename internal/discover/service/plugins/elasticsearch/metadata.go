// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package elasticsearch

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceElasticsearch struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (ServiceElasticsearch) Type() common.ProtocolType { return common.ProtocolTypeElasticsearch }
