// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package neo4j

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceNeo4j struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (ServiceNeo4j) Type() common.ProtocolType { return common.ProtocolTypeNeo4J }
