package elasticsearch

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

const (
	ELASTICSEARCH            = "elasticsearch"
	DefaultElasticsearchPort = 9200
	ElasticsearchTagline     = "You Know, for Search"
)

// elasticsearchRootResponse represents the JSON response from Elasticsearch root endpoint
type elasticsearchRootResponse struct {
	Name        string               `json:"name"`
	ClusterName string               `json:"cluster_name"`
	ClusterUUID string               `json:"cluster_uuid"`
	Version     elasticsearchVersion `json:"version"`
	Tagline     string               `json:"tagline"`
}

// elasticsearchVersion represents the version object in Elasticsearch response
type elasticsearchVersion struct {
	Number        string `json:"number"`
	BuildFlavor   string `json:"build_flavor"`
	BuildType     string `json:"build_type"`
	BuildHash     string `json:"build_hash"`
	BuildDate     string `json:"build_date"`
	BuildSnapshot bool   `json:"build_snapshot"`
	LuceneVersion string `json:"lucene_version"`
}
type ElasticsearchPlugin struct{}

// versionCleanupRegex removes -SNAPSHOT suffix from versions

// detectElasticsearch performs HTTP detection of Elasticsearch service.
// Returns version string (empty if not found) and detection success boolean.
func detectElasticsearch(conn net.Conn, timeout time.Duration) (string, bool, error) {

	httpRequest := "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

	response, err := utils.SendRecv(conn, []byte(httpRequest), timeout)
	if err != nil {
		return "", false, err
	}
	if len(response) == 0 {
		return "", false, &utils.InvalidResponseError{Service: ELASTICSEARCH}
	}

	responseStr := string(response)

	if !strings.Contains(responseStr, "HTTP/1.1 200") && !strings.Contains(responseStr, "HTTP/1.0 200") {

		return "", false, nil
	}

	bodyStart := strings.Index(responseStr, "\r\n\r\n")
	if bodyStart == -1 {
		return "", false, &utils.InvalidResponseError{Service: ELASTICSEARCH}
	}
	jsonBody := responseStr[bodyStart+4:]

	// Parse JSON response
	var esResponse elasticsearchRootResponse
	err = json.Unmarshal([]byte(jsonBody), &esResponse)
	if err != nil {

		return "", false, nil
	}

	if esResponse.Tagline != ElasticsearchTagline {

		return "", false, nil
	}

	if esResponse.Version.Number == "" {

		return "", true, nil
	}

	version := cleanVersionString(esResponse.Version.Number)

	return version, true, nil
}

// cleanVersionString removes -SNAPSHOT suffix from version strings.
// Preserves RC tags (e.g., "8.0.0-rc2" remains as-is).
func cleanVersionString(version string) string {

	if strings.HasSuffix(version, "-SNAPSHOT") {
		version = strings.TrimSuffix(version, "-SNAPSHOT")
	}
	return version
}

// buildElasticsearchCPE generates a CPE (Common Platform Enumeration) string for Elasticsearch.
// CPE format: cpe:2.3:a:elastic:elasticsearch:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to match Wappalyzer/RMI/FTP
// plugin behavior and enable asset inventory use cases.
func buildElasticsearchCPE(version string) string {

	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:elastic:elasticsearch:%s:*:*:*:*:*:*:*", version)
}
func (p *ElasticsearchPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	version, detected, err := detectElasticsearch(conn, timeout)
	if err != nil {
		return nil, err
	}
	if !detected {
		return nil, nil
	}

	cpe := buildElasticsearchCPE(version)
	payload := probe.ServiceElasticsearch{
		CPEs: []string{cpe},
	}

	return probe.Result(target, payload, false, version, probe.TCP), nil
}
func (p *ElasticsearchPlugin) PortPriority(port uint16) bool {
	return port == DefaultElasticsearchPort
}
func (p *ElasticsearchPlugin) Name() string {
	return ELASTICSEARCH
}
func (p *ElasticsearchPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *ElasticsearchPlugin) Priority() int {
	return 100
}

var defaultElasticsearchPluginPorts = probe.Ports((&ElasticsearchPlugin{}).PortPriority)

func (p *ElasticsearchPlugin) DefaultPorts() []int { return defaultElasticsearchPluginPorts }
func (p *ElasticsearchPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
