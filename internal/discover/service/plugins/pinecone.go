package plugins

import (
	"context"
	"net"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type PineconeFingerprinter struct{}

func (PineconeFingerprinter) Name() string        { return "pinecone" }
func (PineconeFingerprinter) DefaultPorts() []int { return []int{443} }
func (PineconeFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	p := newProductHTTP(ip, port, host, timeout, true)
	defer p.transport.CloseIdleConnections()
	r, _, err := p.get(ctx, "/")
	if err != nil {
		return nil, err
	}
	// Generic Envoy, JSON, or authentication errors are not product evidence.
	branded := false
	for _, key := range []string{"X-Pinecone-Api-Version", "X-Pinecone-Request-Id", "X-Pinecone-Lsn-Reconciled", "X-Pinecone-Lsn-Committed"} {
		if r.Header.Get(key) != "" {
			branded = true
		}
	}
	server := strings.ToLower(r.Header.Get("Server"))
	if server == "pinecone" || strings.HasPrefix(server, "pinecone/") {
		branded = true
	}
	if !branded {
		return nil, nil
	}
	return productHTTPResult(host, ip, port, true, common.ProtocolTypePinecone, "pinecone", "", r, map[string]string{"apiVersion": r.Header.Get("X-Pinecone-Api-Version")}), nil
}
