package plugins

import (
	"context"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type MilvusMetricsFingerprinter struct{}

func (MilvusMetricsFingerprinter) Name() string        { return "milvus-metrics" }
func (MilvusMetricsFingerprinter) DefaultPorts() []int { return []int{9091} }
func (MilvusMetricsFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	for _, secure := range []bool{false, true} {
		p := newProductHTTP(ip, port, host, timeout, secure)
		r, b, err := p.get(ctx, "/metrics")
		p.transport.CloseIdleConnections()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil || r.StatusCode != 200 {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			m := milvusBuildSample.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			value, err := strconv.ParseFloat(m[2], 64)
			if err != nil || value != 1 {
				continue
			}
			metadata := map[string]string{"discovery": "metrics"}
			for _, label := range milvusBuildLabel.FindAllStringSubmatch(m[1], -1) {
				value, err := strconv.Unquote(label[2])
				if err == nil {
					metadata[label[1]] = value
				}
			}
			return productHTTPResult(host, ip, port, secure, common.ProtocolTypeMilvus, "milvus-metrics", metadata["version"], r, metadata), nil
		}
	}
	return nil, nil
}

// Match a complete build-info sample, never HELP text or an arbitrary substring.
const milvusLabelPattern = `[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*"(?:[^"\\\n]|\\[\\"n])*"`

var milvusBuildSample = regexp.MustCompile(`^\s*milvus_build_info\{\s*((?:` + milvusLabelPattern + `(?:\s*,\s*` + milvusLabelPattern + `)*\s*,?)?)\s*\}\s+(\S+)(?:\s+-?[0-9]+)?\s*$`)
var milvusBuildLabel = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*("(?:[^"\\\n]|\\[\\"n])*")`)
