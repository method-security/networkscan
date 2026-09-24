package plugins

import (
	"context"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	discover "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type CouchDBFingerprinter struct{}
type CouchDBTLSFingerprinter struct{}

func (CouchDBFingerprinter) Name() string           { return "couchdb" }
func (CouchDBTLSFingerprinter) Name() string        { return "couchdb" }
func (CouchDBFingerprinter) DefaultPorts() []int    { return []int{5984} }
func (CouchDBTLSFingerprinter) DefaultPorts() []int { return []int{6984} }
func (CouchDBFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return discoverCouchDB(ctx, ip, port, host, timeout, false)
}
func (CouchDBTLSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	return discoverCouchDB(ctx, ip, port, host, timeout, true)
}

// CouchDB documents the welcome object at GET / in its server API.
func discoverCouchDB(ctx context.Context, ip net.IP, port int, host string, timeout int, secure bool) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	p := newProductHTTP(ip, port, host, timeout, secure)
	defer p.transport.CloseIdleConnections()
	r, b, err := p.get(ctx, "/")
	if err != nil {
		return nil, err
	}
	o := productJSON(b)
	version := productString(o, "version")
	if r.StatusCode != 200 || productString(o, "couchdb") != "Welcome" || version == "" {
		return nil, nil
	}
	m := productFields(o, "uuid", "git_sha")
	m["vendor"] = productString(productJSON(o["vendor"]), "name")
	if features, ok := o["features"]; ok {
		m["features"] = string(features)
	}
	return productHTTPResult(host, ip, port, secure, common.ProtocolTypeCouchdb, "couchdb", version, r, m), nil
}
