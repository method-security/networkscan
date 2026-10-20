// Package plugins provides etcd service fingerprinting via the HTTP/JSON gateway
package plugins

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type EtcdFingerprinter struct{}

func (EtcdFingerprinter) Name() string        { return "etcd" }
func (EtcdFingerprinter) DefaultPorts() []int { return []int{2379} }

func (EtcdFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	timeoutDuration := time.Duration(timeout) * time.Second
	if timeoutDuration <= 0 {
		timeoutDuration = 5 * time.Second
	}
	// Try plain HTTP first, then HTTPS with InsecureSkipVerify
	for _, scheme := range []string{"http", "https"} {
		p := newProductHTTP(ip, port, host, timeout, scheme == "https")
		defer p.transport.CloseIdleConnections()
		client := &http.Client{
			Timeout:       timeoutDuration,
			Transport:     p.transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		}
		versionURL := p.base.String() + "/version"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionURL, nil)
		if err != nil {
			continue
		}
		if userAgent := helpers.HTTPUserAgent(ctx, ""); userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
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
		kubernetesDetected := detectKubernetesEtcd(ctx, client, p.base.String())
		serverInfo.KubernetesDetected = &kubernetesDetected

		return buildEtcdServiceResult(host, ip, port, scheme == "https", serverInfo), nil
	}
	return nil, nil
}

func detectKubernetesEtcd(ctx context.Context, client *http.Client, baseURL string) bool {
	metricsURL := baseURL + "/metrics"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metricsURL, nil)
	if err != nil {
		return false
	}
	if userAgent := helpers.HTTPUserAgent(ctx, ""); userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
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

func buildEtcdServiceResult(host string, ip net.IP, port int, tlsEnabled bool, serverInfo *protocol.EtcdServerInfo) *discoverfern.ServiceDetails {
	hostname := host
	if hostname == "" {
		hostname = ip.String()
	}

	return &discoverfern.ServiceDetails{
		Host:      hostname,
		Ip:        ip.String(),
		Port:      port,
		Tls:       helpers.BoolPtr(tlsEnabled),
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeEtcd,
		Metadata:  &discoverfern.ServiceMetadata{Etcd: serverInfo},
	}
}
