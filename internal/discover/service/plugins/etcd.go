// Package plugins provides etcd service fingerprinting via the HTTP/JSON gateway
package plugins

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type EtcdFingerprinter struct{}

func (EtcdFingerprinter) Name() string        { return "etcd" }
func (EtcdFingerprinter) DefaultPorts() []int { return []int{2379} }

func (EtcdFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	timeoutDuration := time.Duration(timeout) * time.Second
	if timeoutDuration <= 0 {
		timeoutDuration = 5 * time.Second
	}
	addr := fmt.Sprintf("%s:%d", ip.String(), port)

	// Try plain HTTP first, then HTTPS with InsecureSkipVerify
	for _, scheme := range []string{"http", "https"} {
		var client *http.Client
		if scheme == "https" {
			client = &http.Client{
				Timeout: timeoutDuration,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
				},
			}
		} else {
			client = &http.Client{Timeout: timeoutDuration}
		}

		versionURL := fmt.Sprintf("%s://%s/version", scheme, addr)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionURL, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		// Parse etcd version response: {"etcdserver":"3.5.0","etcdcluster":"3.5.0"}
		var versionResp struct {
			EtcdServer  string `json:"etcdserver"`
			EtcdCluster string `json:"etcdcluster"`
		}
		if err := json.Unmarshal(body, &versionResp); err != nil || versionResp.EtcdServer == "" {
			continue
		}

		serverVersion := versionResp.EtcdServer
		clusterVersion := versionResp.EtcdCluster

		serverInfo := &protocol.EtcdServerInfo{
			ServerVersion:  &serverVersion,
			ClusterVersion: &clusterVersion,
		}

		// Try to detect Kubernetes etcd via /metrics
		kubernetesDetected := detectKubernetesEtcd(ctx, client, scheme, addr)
		serverInfo.KubernetesDetected = &kubernetesDetected

		return buildEtcdServiceResult(host, ip, port, serverInfo), nil
	}
	return nil, nil
}

func detectKubernetesEtcd(ctx context.Context, client *http.Client, scheme, addr string) bool {
	metricsURL := fmt.Sprintf("%s://%s/metrics", scheme, addr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metricsURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	metrics := string(bodyBytes)
	// If etcd metrics present with both these indicators, tag as potentially k8s
	return strings.Contains(metrics, "etcd_mvcc_db_total_size") && strings.Contains(metrics, "etcd_server_version")
}

func buildEtcdServiceResult(host string, ip net.IP, port int, serverInfo *protocol.EtcdServerInfo) *discoverfern.ServiceDetails {
	hostname := host
	if hostname == "" {
		hostname = ip.String()
	}

	return &discoverfern.ServiceDetails{
		Host:      hostname,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeUnknown,
		Metadata:  &discoverfern.ServiceMetadata{Etcd: serverInfo},
	}
}
