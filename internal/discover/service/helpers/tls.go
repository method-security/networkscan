package helpers

import (
	"context"
	"crypto/tls"
	"net"
)

func UpgradeTLS(ctx context.Context, conn net.Conn, host string) (net.Conn, error) {
	secure := tls.Client(conn, DiscoveryTLSConfig(host))
	if err := secure.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return secure, nil
}

// DiscoveryTLSConfig permits legacy services to identify themselves. It must not
// be used for authenticated application traffic.
func DiscoveryTLSConfig(host string) *tls.Config {
	config := &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS10} //nolint:gosec // Service discovery intentionally probes legacy and self-signed endpoints.
	for _, suites := range [][]*tls.CipherSuite{tls.CipherSuites(), tls.InsecureCipherSuites()} {
		for _, suite := range suites {
			config.CipherSuites = append(config.CipherSuites, suite.ID)
		}
	}
	return config
}
