package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

const productBodyLimit = 1 << 20

// Each probe owns a transport so connections never escape the attempt's context.
type productHTTP struct {
	base      url.URL
	transport *http.Transport
}

func newProductHTTP(ip net.IP, port int, host string, timeout int, secure bool) *productHTTP {
	if host == "" {
		host = ip.String()
	}
	scheme := "http"
	if secure {
		scheme = "https"
	}
	t := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return helpers.TCPConn(ctx, ip, port, timeout)
		},
		TLSClientConfig:        helpers.DiscoveryTLSConfig(host),
		MaxResponseHeaderBytes: 64 << 10,
		DisableKeepAlives:      true,
	}
	authority := net.JoinHostPort(host, strconv.Itoa(port))
	if (!secure && port == 80) || (secure && port == 443) {
		authority = host
		if strings.Contains(host, ":") {
			authority = "[" + host + "]"
		}
	}
	return &productHTTP{transport: t, base: url.URL{Scheme: scheme, Host: authority}}
}

func (p *productHTTP) get(ctx context.Context, path string) (*http.Response, []byte, error) {
	u := p.base
	u.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "networkscan")
	// RoundTrip preserves valid responses even when Location is malformed;
	// discovery never follows redirects to another endpoint.
	r, err := p.transport.RoundTrip(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = r.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(r.Body, productBodyLimit+1))
	if len(b) > productBodyLimit {
		return r, b[:productBodyLimit], fmt.Errorf("HTTP discovery body exceeds %d bytes", productBodyLimit)
	}
	return r, b, err
}

func productHTTPResult(host string, ip net.IP, port int, secure bool, protocol common.ProtocolType, name, version string, r *http.Response, metadata map[string]string) *discover.ServiceDetails {
	if metadata == nil {
		metadata = map[string]string{}
	}
	if identity := productCPEIdentity[name]; identity != "" {
		// Only plain release versions are safely bound without guessing how
		// vendor suffixes map to CPE's separate update component.
		cpeVersion := strings.TrimPrefix(version, "v")
		if !productCPERelease.MatchString(cpeVersion) {
			cpeVersion = "*"
		}
		cpes, _ := json.Marshal([]string{"cpe:2.3:a:" + identity + ":" + cpeVersion + ":*:*:*:*:*:*:*"})
		metadata["cpes"] = string(cpes)
	}
	metadata["scheme"] = "http"
	if secure {
		metadata["scheme"] = "https"
	}
	if r != nil {
		metadata["status"] = r.Status
		metadata["statusCode"] = strconv.Itoa(r.StatusCode)
		metadata["server"] = r.Header.Get("Server")
		headers, _ := json.Marshal(r.Header)
		metadata["responseHeaders"] = string(headers)
	}
	result := helpers.GenericResult(host, ip, port, common.TransportTypeTcp, protocol, name, version, metadata)
	result.Tls = helpers.BoolPtr(secure)
	return result
}

// Vendor/product identifiers are from the NVD CPE dictionary, not banner text.
var productCPEIdentity = map[string]string{
	"couchdb":       "apache:couchdb",
	"elasticsearch": "elastic:elasticsearch",
	"influxdb":      "influxdata:influxdb",
	"kubernetes":    "kubernetes:kubernetes",
}
var productCPERelease = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)+$`)

func productJSON(body []byte) map[string]json.RawMessage {
	var object map[string]json.RawMessage
	if json.Unmarshal(body, &object) != nil {
		return nil
	}
	return object
}

func productString(object map[string]json.RawMessage, key string) string {
	var value string
	_ = json.Unmarshal(object[key], &value)
	return value
}

func productFields(object map[string]json.RawMessage, keys ...string) map[string]string {
	m := map[string]string{}
	for _, key := range keys {
		if value := productString(object, key); value != "" {
			m[key] = value
		}
	}
	return m
}
