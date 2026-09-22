// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package imap

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceIMAP struct {
	Banner string `json:"banner"`
}

func (ServiceIMAP) Type() common.ProtocolType { return common.ProtocolTypeImap }

type ServiceIMAPS struct {
	Banner string `json:"banner"`
}

func (ServiceIMAPS) Type() common.ProtocolType { return common.ProtocolTypeImaps }
