// Package plugins provides LDAP service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/go-ldap/ldap/v3"
)

type LDAPFingerprinter struct{}

func (LDAPFingerprinter) Name() string { return "ldap" }

func (LDAPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Create a context with 10-second timeout
	_, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Use proper LDAP client with timeout
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s", addr), ldap.DialWithDialer(&net.Dialer{
		Timeout: 10 * time.Second,
	}))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Try anonymous bind to test LDAP service
	err = conn.UnauthenticatedBind("")
	if err != nil {
		// Even if bind fails, if we got an LDAP error, the service is running
		if strings.Contains(err.Error(), "LDAP") || strings.Contains(err.Error(), "ldap") {
			metadata := &protocol.LdapServerInfo{}
			return &discoverfern.ServiceDetails{
				Host:      host,
				Ip:        ip.String(),
				Port:      port,
				Tls:       false,
				Transport: common.TransportTypeTcp,
				Protocol:  common.ProtocolTypeLdap,
				Metadata:  discoverfern.NewServiceMetadataFromLdap(metadata),
			}, nil
		}
		return nil, err
	}

	// Successful anonymous bind
	anonymousAllowed := true
	metadata := &protocol.LdapServerInfo{
		AnonymousBindAllowed: &anonymousAllowed,
	}
	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeLdap,
		Metadata:  discoverfern.NewServiceMetadataFromLdap(metadata),
	}, nil
}
