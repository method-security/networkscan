package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type HTTPPlugin struct {
	analyzer *wappalyzer.Wappalyze
}
type HTTPSPlugin struct {
	analyzer *wappalyzer.Wappalyze
}

const HTTP = "http"
const HTTPS = "https"
const USERAGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

var (
	commonHTTPPorts = map[int]struct{}{
		80:   {},
		3000: {},
		4567: {},
		5000: {},
		8000: {},
		8001: {},
		8080: {},
		8081: {},
		8888: {},
		9001: {},
		9080: {},
		9090: {},
		9100: {},
	}

	commonHTTPSPorts = map[int]struct{}{
		443:  {},
		8443: {},
		9443: {},
	}
)

func (p *HTTPPlugin) PortPriority(port uint16) bool {
	_, ok := commonHTTPPorts[int(port)]
	return ok
}
func (p *HTTPPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s", conn.RemoteAddr().String()), nil)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, nil
		}
		return nil, &utils.RequestError{Message: err.Error()}
	}

	if target.Host != "" {
		req.Host = target.Host
	}

	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req.Header.Set("User-Agent", USERAGENT)

	resp, err := client.Do(req)
	if err != nil {
		return nil, &utils.RequestError{Message: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()

	technologies, cpes, _ := p.FingerprintResponse(resp)

	payload := probe.ServiceHTTP{
		Status:          resp.Status,
		StatusCode:      resp.StatusCode,
		ResponseHeaders: resp.Header,
	}
	if len(technologies) > 0 {
		payload.Technologies = technologies
	}
	if len(cpes) > 0 {
		payload.CPEs = cpes
	}

	return probe.Result(target, payload, false, resp.Header.Get("Server"), probe.TCP), nil
}
func (p *HTTPSPlugin) PortPriority(port uint16) bool {
	_, ok := commonHTTPSPorts[int(port)]
	return ok
}
func (p *HTTPSPlugin) Run(
	conn net.Conn,
	timeout time.Duration,
	target probe.Target,
) (*probe.Service, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s", conn.RemoteAddr().String()), nil)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, nil
		}
		return nil, &utils.RequestError{Message: err.Error()}
	}

	if target.Host != "" {
		req.Host = target.Host
	}

	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req.Header.Set("User-Agent", USERAGENT)

	resp, err := client.Do(req)
	if err != nil {
		return nil, &utils.RequestError{Message: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()

	technologies, cpes, _ := p.FingerprintResponse(resp)

	payload := probe.ServiceHTTPS{
		Status:          resp.Status,
		StatusCode:      resp.StatusCode,
		ResponseHeaders: resp.Header,
	}
	if len(technologies) > 0 {
		payload.Technologies = technologies
	}
	if len(cpes) > 0 {
		payload.CPEs = cpes
	}

	return probe.Result(target, payload, true, resp.Header.Get("Server"), probe.TCP), nil
}
func (p *HTTPPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *HTTPSPlugin) Type() probe.Protocol {
	return probe.TCPTLS
}
func (p *HTTPPlugin) Priority() int {
	return 0
}
func (p *HTTPSPlugin) Priority() int {
	return 1
}
func (p *HTTPPlugin) Name() string {
	return HTTP
}
func (p *HTTPSPlugin) Name() string {
	return HTTPS
}
func (p *HTTPPlugin) FingerprintResponse(resp *http.Response) ([]string, []string, error) {
	return fingerprint(resp, p.analyzer)
}
func (p *HTTPSPlugin) FingerprintResponse(resp *http.Response) ([]string, []string, error) {
	return fingerprint(resp, p.analyzer)
}
func fingerprint(resp *http.Response, analyzer *wappalyzer.Wappalyze) ([]string, []string, error) {
	if analyzer == nil {
		analyzer = httpAnalyzer()
	}
	if analyzer == nil {
		return nil, nil, fmt.Errorf("HTTP analyzer unavailable")
	}
	var technologies, cpes []string
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}

	fingerprint := analyzer.FingerprintWithInfo(resp.Header, data)
	for tech, appInfo := range fingerprint {
		technologies = append(technologies, tech)
		if cpe := appInfo.CPE; cpe != "" {
			cpes = append(cpes, cpe)
		}
	}

	return technologies, cpes, nil
}

var httpAnalyzer = sync.OnceValue(func() *wappalyzer.Wappalyze {
	analyzer, err := wappalyzer.New()
	if err != nil {
		return nil
	}
	return analyzer
})

var defaultHTTPPluginPorts = probe.Ports((&HTTPPlugin{}).PortPriority)

func (p *HTTPPlugin) DefaultPorts() []int { return defaultHTTPPluginPorts }
func (p *HTTPPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}

var defaultHTTPSPluginPorts = probe.Ports((&HTTPSPlugin{}).PortPriority)

func (p *HTTPSPlugin) DefaultPorts() []int { return defaultHTTPSPluginPorts }
func (p *HTTPSPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
