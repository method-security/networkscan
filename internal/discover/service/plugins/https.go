package plugins

import (
	"context"
	"encoding/json"
	"net"
	"sort"
	"sync"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// HTTPDiscoveryFingerprinter supplies bounded, hostname-aware discovery while the
// original HTTPFingerprinter implementation remains untouched.
type HTTPDiscoveryFingerprinter struct{}
type HTTPSFingerprinter struct{}

func (HTTPDiscoveryFingerprinter) Name() string { return "http" }
func (HTTPDiscoveryFingerprinter) DefaultPorts() []int {
	return []int{80, 3000, 4567, 5000, 8000, 8001, 8080, 8081, 8888, 9001, 9080, 9090, 9100}
}
func (HTTPSFingerprinter) Name() string        { return "https" }
func (HTTPSFingerprinter) DefaultPorts() []int { return []int{443, 8443, 9443} }
func (HTTPDiscoveryFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return discoverNativeHTTP(ctx, ip, port, host, timeout, false)
}
func (HTTPSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return discoverNativeHTTP(ctx, ip, port, host, timeout, true)
}

var httpProductAnalyzer = sync.OnceValues(wappalyzer.New)

func discoverNativeHTTP(ctx context.Context, ip net.IP, port int, host string, timeout int, secure bool) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	p := newProductHTTP(ip, port, host, timeout, secure)
	defer p.transport.CloseIdleConnections()
	r, body, err := p.get(ctx, "/")
	if r == nil {
		return nil, err
	}
	metadata := map[string]string{}
	if err != nil {
		metadata["bodyIncomplete"] = "true"
	}
	// Technology matching is optional enrichment; bound its CPU work as well as I/O.
	if len(body) > 32<<10 {
		body = body[:32<<10]
		metadata["analysisTruncated"] = "true"
	}
	if analyzer, err := httpProductAnalyzer(); err == nil {
		apps, title := analyzer.FingerprintWithTitle(r.Header, body)
		technologies := make([]string, 0, len(apps))
		for app := range apps {
			technologies = append(technologies, app)
		}
		sort.Strings(technologies)
		encoded, _ := json.Marshal(technologies)
		metadata["technologies"] = string(encoded)
		metadata["title"] = title
		var cpes []string
		for _, info := range analyzer.FingerprintWithInfo(r.Header, body) {
			if info.CPE != "" {
				cpes = append(cpes, info.CPE)
			}
		}
		sort.Strings(cpes)
		if len(cpes) > 0 {
			encoded, _ := json.Marshal(cpes)
			metadata["cpes"] = string(encoded)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	protocol, name := common.ProtocolTypeHttp, "http"
	if secure {
		protocol, name = common.ProtocolTypeHttps, "https"
	}
	return productHTTPResult(host, ip, port, secure, protocol, name, r.Header.Get("Server"), r, metadata), nil
}
