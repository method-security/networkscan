// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package kubernetes

import (
	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceKubernetes struct {
	CPEs         []string `json:"cpes,omitempty"`
	GitVersion   string   `json:"gitVersion,omitempty"`
	GitCommit    string   `json:"gitCommit,omitempty"`
	BuildDate    string   `json:"buildDate,omitempty"`
	GoVersion    string   `json:"goVersion,omitempty"`
	Platform     string   `json:"platform,omitempty"`
	Distribution string   `json:"distribution,omitempty"`
	Vendor       string   `json:"vendor,omitempty"`
}

func (ServiceKubernetes) Type() common.ProtocolType { return common.ProtocolTypeKubernetes }
