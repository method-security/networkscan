// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package http

import (
	"net/http"

	"github.com/Method-Security/networkscan/generated/go/common"
)

type ServiceHTTP struct {
	Status          string      `json:"status"`
	StatusCode      int         `json:"statusCode"`
	ResponseHeaders http.Header `json:"responseHeaders"`
	Technologies    []string    `json:"technologies,omitempty"`
	CPEs            []string    `json:"cpes,omitempty"`
}

func (ServiceHTTP) Type() common.ProtocolType { return common.ProtocolTypeHttp }

type ServiceHTTPS struct {
	Status          string      `json:"status"`
	StatusCode      int         `json:"statusCode"`
	ResponseHeaders http.Header `json:"responseHeaders"`
	Technologies    []string    `json:"technologies,omitempty"`
	CPEs            []string    `json:"cpes,omitempty"`
}

func (ServiceHTTPS) Type() common.ProtocolType { return common.ProtocolTypeHttps }
