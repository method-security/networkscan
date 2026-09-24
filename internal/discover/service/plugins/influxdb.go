package plugins

import (
	"context"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type InfluxDBFingerprinter struct{}

func (InfluxDBFingerprinter) Name() string        { return "influxdb" }
func (InfluxDBFingerprinter) DefaultPorts() []int { return []int{8086} }
func (InfluxDBFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	for _, secure := range []bool{false, true} {
		p := newProductHTTP(ip, port, host, timeout, secure)
		for _, path := range []string{"/health", "/ping"} {
			r, b, err := p.get(ctx, path)
			if ctx.Err() != nil {
				p.transport.CloseIdleConnections()
				return nil, ctx.Err()
			}
			if err != nil {
				break
			}
			o := productJSON(b)
			version := r.Header.Get("X-Influxdb-Version")
			branded := version != ""
			if !branded && !(path == "/health" && productString(o, "name") == "influxdb" && (productString(o, "status") == "pass" || productString(o, "status") == "fail") && (r.StatusCode == 200 || r.StatusCode == 503)) {
				continue
			}
			if version == "" {
				version = productString(o, "version")
			}
			m := productFields(o, "name", "message", "status", "commit")
			m["build"] = r.Header.Get("X-Influxdb-Build")
			p.transport.CloseIdleConnections()
			return productHTTPResult(host, ip, port, secure, common.ProtocolTypeInfluxdb, "influxdb", version, r, m), nil
		}
		p.transport.CloseIdleConnections()
	}
	return nil, nil
}
