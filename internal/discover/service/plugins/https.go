package plugins

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

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
	requestCtx, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()
	r, err := p.getResponse(requestCtx, "/")
	if r == nil {
		return nil, err
	}
	defer func() { _ = r.Body.Close() }()

	// Body and technology enrichment are optional once headers identify HTTP.
	// Leave half the remaining attempt budget available to return that evidence.
	enrichmentBudget := time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline) / 2; remaining < enrichmentBudget {
			enrichmentBudget = remaining
		}
	}
	enrichmentCtx, cancelEnrichment := context.WithTimeout(ctx, enrichmentBudget)
	defer cancelEnrichment()
	stopCancel := context.AfterFunc(enrichmentCtx, cancelRequest)
	defer stopCancel()
	body, bodyErr := readProductHTTPBody(r.Body)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if isHTTPFrontingError(r.StatusCode, body) {
		return nil, nil
	}
	metadata := map[string]string{}
	if bodyErr != nil {
		metadata["bodyIncomplete"] = "true"
	}
	// Technology matching is optional enrichment; bound its CPU work as well as I/O.
	if len(body) > 32<<10 {
		body = body[:32<<10]
		metadata["analysisTruncated"] = "true"
	}
	protocol, name := common.ProtocolTypeHttp, "http"
	if secure {
		protocol, name = common.ProtocolTypeHttps, "https"
	}
	result := productHTTPResult(host, ip, port, secure, protocol, name, r.Header.Get("Server"), r, metadata)
	if enrichmentCtx.Err() != nil {
		metadata["analysisIncomplete"] = "true"
		return result, nil
	}

	// Analysis owns its metadata so a late completion cannot mutate a returned result.
	analysis := make(chan map[string]string, 1)
	go func() {
		defer func() {
			if recover() != nil {
				analysis <- map[string]string{"analysisIncomplete": "true"}
			}
		}()
		analysis <- analyzeNativeHTTP(r.Header, body)
	}()
	select {
	case enrichment := <-analysis:
		for key, value := range enrichment {
			metadata[key] = value
		}
	case <-enrichmentCtx.Done():
		metadata["analysisIncomplete"] = "true"
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func analyzeNativeHTTP(headers http.Header, body []byte) map[string]string {
	metadata := map[string]string{}
	if analyzer, err := httpProductAnalyzer(); err == nil {
		apps, title := analyzer.FingerprintWithTitle(headers, body)
		technologies := make([]string, 0, len(apps))
		for app := range apps {
			technologies = append(technologies, app)
		}
		sort.Strings(technologies)
		encoded, _ := json.Marshal(technologies)
		metadata["technologies"] = string(encoded)
		metadata["title"] = title
		var cpes []string
		for _, info := range analyzer.FingerprintWithInfo(headers, body) {
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
	return metadata
}

func isHTTPFrontingError(statusCode int, body []byte) bool {
	_ = statusCode
	lowerBody := strings.ToLower(string(body))
	for _, marker := range []string{
		"400 bad request",
		"http request to a https server",
		"http request to an https server",
		"plain http request was sent to https port",
		"speaking plain http to an ssl-enabled server port",
	} {
		if strings.Contains(lowerBody, marker) {
			return true
		}
	}
	return false
}
