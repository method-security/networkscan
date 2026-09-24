package plugins

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type KubernetesFingerprinter struct{}

func (KubernetesFingerprinter) Name() string        { return "kubernetes" }
func (KubernetesFingerprinter) DefaultPorts() []int { return []int{6443} }
func (KubernetesFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	for _, secure := range []bool{true, false} {
		p := newProductHTTP(ip, port, host, timeout, secure)
		r, b, err := p.get(ctx, "/version")
		if ctx.Err() != nil {
			p.transport.CloseIdleConnections()
			return nil, ctx.Err()
		}
		if err != nil {
			p.transport.CloseIdleConnections()
			continue
		}
		o := productJSON(b)
		version := productString(o, "gitVersion")
		// The version.Info schema is shared by other Go projects. Confirm the
		// Kubernetes discovery object or canonical authorization Status as well.
		if r.StatusCode != 200 || !strings.HasPrefix(version, "v") || productString(o, "major") == "" || productString(o, "minor") == "" || productString(o, "gitCommit") == "" {
			p.transport.CloseIdleConnections()
			continue
		}
		api, body, err := p.get(ctx, "/api")
		p.transport.CloseIdleConnections()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			continue
		}
		a := productJSON(body)
		discovery := api.StatusCode == http.StatusOK && productString(a, "kind") == "APIVersions" && productString(a, "apiVersion") == "v1"
		if !discovery && !kubernetesAPIAuthStatus(api.StatusCode, body) {
			continue
		}
		m := productFields(o, "major", "minor", "gitVersion", "gitCommit", "gitTreeState", "buildDate", "goVersion", "compiler", "platform")
		m["distribution"], m["vendor"] = "vanilla", "kubernetes"
		for _, dist := range []struct{ marker, name, vendor string }{{"k3s", "k3s", "rancher"}, {"rke2", "rke2", "rancher"}, {"gke", "gke", "google"}, {"eks", "eks", "aws"}, {"aks", "aks", "azure"}} {
			if strings.Contains(strings.ToLower(version), dist.marker) {
				m["distribution"], m["vendor"] = dist.name, dist.vendor
				break
			}
		}
		return productHTTPResult(host, ip, port, secure, common.ProtocolTypeKubernetes, "kubernetes", version, r, m), nil
	}
	return nil, nil
}

// Status follows apimachinery/pkg/apis/meta/v1; require all identity fields
// and matching codes so an ordinary proxy authorization error is not evidence.
func kubernetesAPIAuthStatus(httpCode int, body []byte) bool {
	var expectedReason string
	switch httpCode {
	case http.StatusUnauthorized:
		expectedReason = "Unauthorized"
	case http.StatusForbidden:
		expectedReason = "Forbidden"
	default:
		return false
	}
	var response struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
		Reason     string `json:"reason"`
		Status     string `json:"status"`
		Code       int    `json:"code"`
	}
	return json.Unmarshal(body, &response) == nil && response.Kind == "Status" &&
		response.APIVersion == "v1" && response.Reason == expectedReason &&
		response.Status == "Failure" && response.Code == httpCode
}
