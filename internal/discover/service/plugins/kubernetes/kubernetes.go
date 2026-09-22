// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package kubernetes

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type KubernetesPlugin struct{}

const KUBERNETES = "kubernetes"

// VersionInfo represents the structure of Kubernetes /version endpoint response
type VersionInfo struct {
	Major        string `json:"major"`
	Minor        string `json:"minor"`
	GitVersion   string `json:"gitVersion"`
	GitCommit    string `json:"gitCommit"`
	GitTreeState string `json:"gitTreeState"`
	BuildDate    string `json:"buildDate"`
	GoVersion    string `json:"goVersion"`
	Compiler     string `json:"compiler"`
	Platform     string `json:"platform"`
}

func (p *KubernetesPlugin) PortPriority(port uint16) bool {

	return port == 6443
}
func (p *KubernetesPlugin) Name() string {
	return KUBERNETES
}
func (p *KubernetesPlugin) Type() common.TransportType {
	return common.TransportTypeTcptls
}
func (p *KubernetesPlugin) Priority() int {

	return 30
}
func (p *KubernetesPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {

	_, isTLS := conn.(*tls.Conn)

	// Create HTTP client that uses the provided connection
	// If connection is already TLS, don't wrap it again
	var transport *http.Transport
	var scheme string

	if isTLS {

		scheme = "http"
		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		}
	} else {

		scheme = "https"
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		}
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	versionURL := fmt.Sprintf("%s://%s/version", scheme, conn.RemoteAddr().String())
	req, err := http.NewRequest("GET", versionURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "networkscan")

	if target.Host != "" {
		req.Host = target.Host
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil
	}

	versionInfo, err := checkKubernetesVersion(body)
	if err != nil {
		return nil, nil
	}

	major, minor, patch := extractKubernetesVersion(versionInfo.GitVersion)
	version := fmt.Sprintf("%s.%s.%s", major, minor, patch)

	distribution, vendor := detectDistribution(versionInfo.GitVersion)

	cpe := buildKubernetesCPE(version, vendor)

	payload := ServiceKubernetes{
		CPEs:         []string{cpe},
		GitVersion:   versionInfo.GitVersion,
		GitCommit:    versionInfo.GitCommit,
		BuildDate:    versionInfo.BuildDate,
		GoVersion:    versionInfo.GoVersion,
		Platform:     versionInfo.Platform,
		Distribution: distribution,
		Vendor:       vendor,
	}

	return helpers.MetadataResult(target, payload, true, version, common.TransportTypeTcptls), nil
}

// checkKubernetesVersion validates that the response is from a Kubernetes API server
// by checking the required fields and gitVersion format
func checkKubernetesVersion(data []byte) (VersionInfo, error) {
	var versionInfo VersionInfo

	err := json.Unmarshal(data, &versionInfo)
	if err != nil {
		return VersionInfo{}, fmt.Errorf("%s: invalid response: %s", KUBERNETES,
			"invalid JSON response")

	}

	if versionInfo.Major == "" {
		return VersionInfo{}, fmt.Errorf("%s: invalid response: %s", KUBERNETES,
			"missing major field")

	}
	if versionInfo.Minor == "" {
		return VersionInfo{}, fmt.Errorf("%s: invalid response: %s", KUBERNETES,
			"missing minor field")

	}
	if versionInfo.GitVersion == "" {
		return VersionInfo{}, fmt.Errorf("%s: invalid response: %s", KUBERNETES,
			"missing gitVersion field")

	}

	gitVersionRegex := regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+`)
	if !gitVersionRegex.MatchString(versionInfo.GitVersion) {
		return VersionInfo{}, fmt.Errorf("%s: invalid response: %s", KUBERNETES,
			"invalid gitVersion format")

	}

	return versionInfo, nil
}

// extractKubernetesVersion extracts major, minor, patch from gitVersion field
// Examples:
//   - v1.28.3 -> 1, 28, 3
//   - v1.29.0-alpha.1 -> 1, 29, 0
//   - v1.28.3+k3s1 -> 1, 28, 3
func extractKubernetesVersion(gitVersion string) (major, minor, patch string) {
	if gitVersion == "" {
		return "", "", ""
	}

	version := strings.TrimPrefix(gitVersion, "v")

	version = strings.Split(version, "-")[0]
	version = strings.Split(version, "+")[0]

	parts := strings.Split(version, ".")
	if len(parts) >= 3 {
		return parts[0], parts[1], parts[2]
	}
	if len(parts) == 2 {
		return parts[0], parts[1], "0"
	}
	if len(parts) == 1 {
		return parts[0], "0", "0"
	}

	return "", "", ""
}

// detectDistribution identifies Kubernetes distribution and vendor from gitVersion suffix
func detectDistribution(gitVersion string) (distribution, vendor string) {
	gitLower := strings.ToLower(gitVersion)

	if strings.Contains(gitLower, "+k3s") {
		return "k3s", "rancher"
	}
	if strings.Contains(gitLower, "+rke2") {
		return "rke2", "rancher"
	}
	if strings.Contains(gitLower, "+gke") {
		return "gke", "google"
	}
	if strings.Contains(gitLower, "+eks") {
		return "eks", "aws"
	}
	if strings.Contains(gitLower, "+aks") {
		return "aks", "azure"
	}
	if strings.Contains(gitLower, "openshift") {
		return "openshift", "redhat"
	}
	if strings.Contains(gitLower, ".minikube") {
		return "minikube", "kubernetes"
	}

	return "vanilla", "kubernetes"
}

// buildKubernetesCPE generates a CPE (Common Platform Enumeration) string for Kubernetes
// CPE format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
func buildKubernetesCPE(version, vendor string) string {

	if version == "" {
		version = "*"
	}

	product := "kubernetes"
	if vendor == "redhat" {
		product = "openshift"
	}

	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}

var defaultKubernetesPluginPorts = helpers.Ports((&KubernetesPlugin{}).PortPriority)

func (p *KubernetesPlugin) DefaultPorts() []int { return defaultKubernetesPluginPorts }
func (p *KubernetesPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
