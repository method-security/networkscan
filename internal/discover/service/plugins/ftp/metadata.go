// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package ftp

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceFTP struct {
	Banner     string   `json:"banner"`
	Confidence string   `json:"confidence,omitempty"`
	CPEs       []string `json:"cpes,omitempty"`
}

func (ServiceFTP) Type() common.ProtocolType { return common.ProtocolTypeFtp }
