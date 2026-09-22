// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package couchdb

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceCouchDB struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (ServiceCouchDB) Type() common.ProtocolType { return common.ProtocolTypeCouchdb }
