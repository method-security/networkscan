package plugins

import (
	"context"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type ElasticsearchFingerprinter struct{}

func (ElasticsearchFingerprinter) Name() string        { return "elasticsearch" }
func (ElasticsearchFingerprinter) DefaultPorts() []int { return []int{9200} }
func (ElasticsearchFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	for _, secure := range []bool{false, true} {
		p := newProductHTTP(ip, port, host, timeout, secure)
		r, b, err := p.get(ctx, "/")
		p.transport.CloseIdleConnections()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			continue
		}
		o := productJSON(b)
		v := productJSON(o["version"])
		version := productString(v, "number")
		branded := r.Header.Get("X-Elastic-Product") == "Elasticsearch"
		legacy := productString(o, "tagline") == "You Know, for Search" && productString(o, "cluster_name") != "" && version != "" && productString(v, "lucene_version") != ""
		if !branded && !(r.StatusCode == 200 && legacy) {
			continue
		}
		m := productFields(o, "name", "cluster_name", "cluster_uuid", "tagline")
		for k, value := range productFields(v, "build_flavor", "build_type", "build_hash", "build_date", "lucene_version") {
			m[k] = value
		}
		return productHTTPResult(host, ip, port, secure, common.ProtocolTypeElasticsearch, "elasticsearch", version, r, m), nil
	}
	return nil, nil
}
