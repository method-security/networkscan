package helpers

import (
	"context"
	"crypto/tls"
	"net"
)

func UpgradeTLS(ctx context.Context, conn net.Conn, host string) (net.Conn, error) {
	secure := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host}) //nolint:gosec // Discovery includes self-signed certificates.
	if err := secure.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return secure, nil
}
