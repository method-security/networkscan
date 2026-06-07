package socks

import (
	// Standard
	"context"
	"net"
	"time"

	// Generated
	socksfern "github.com/Method-Security/networkscan/generated/go/enumerate/socks"
)

// dialWithTimeout opens a TCP connection to target, respecting the context deadline
// but also using an explicit dial timeout as a floor.
func dialWithTimeout(ctx context.Context, target string, seconds int) (net.Conn, error) {
	d := net.Dialer{
		Timeout: time.Duration(seconds) * time.Second,
	}
	return d.DialContext(ctx, "tcp", target)
}

// detectImplementationHint applies heuristics to guess the SOCKS server implementation.
func detectImplementationHint(
	port int,
	chosenMethod byte,
	connectRepCode byte,
	bindRepCode *byte,
	responseTimeMs int64,
) socksfern.SocksImplementationHint {
	// Port-based hints
	if torPorts[port] {
		return socksfern.SocksImplementationHintTor
	}

	// BIND rejected with "command not supported" and fast response suggests OpenSSH dynamic
	if bindRepCode != nil && *bindRepCode == 0x07 && responseTimeMs < 100 {
		return socksfern.SocksImplementationHintOpensshDynamic
	}

	// Very fast response with no-auth chosen → likely MicroSocks (minimal implementation)
	if chosenMethod == 0x00 && responseTimeMs < 50 {
		return socksfern.SocksImplementationHintMicrosocks
	}

	// CONNECT succeeded but some commands unsupported → Dante-like
	if connectRepCode == 0x00 && bindRepCode != nil && *bindRepCode == 0x07 {
		return socksfern.SocksImplementationHintDante
	}

	return socksfern.SocksImplementationHintUnknown
}

// parseAuthMethodsFromChoice converts offered methods and server choice into a list.
// Since SOCKS5 only reports one chosen method, we record what we offered as "available"
// based on the server's acceptance.
func parseAuthMethodsFromChoice(offeredMethods []byte, chosenMethod byte) []socksfern.SocksAuthMethod {
	var result []socksfern.SocksAuthMethod

	// If server accepted no-auth, record it
	if chosenMethod == 0x00 {
		result = append(result, socksfern.SocksAuthMethodNoAuth)
	}

	// If server chose username/password, record both no-auth (offered) and username/password
	if chosenMethod == 0x02 {
		result = append(result, socksfern.SocksAuthMethodUsernamePassword)
	}

	// If server chose GSSAPI
	if chosenMethod == 0x01 {
		result = append(result, socksfern.SocksAuthMethodGssapi)
	}

	// Record all methods we offered that weren't chosen as still potentially available
	for _, m := range offeredMethods {
		already := false
		for _, r := range result {
			switch m {
			case 0x00:
				if r == socksfern.SocksAuthMethodNoAuth {
					already = true
				}
			case 0x01:
				if r == socksfern.SocksAuthMethodGssapi {
					already = true
				}
			case 0x02:
				if r == socksfern.SocksAuthMethodUsernamePassword {
					already = true
				}
			}
		}
		if !already {
			switch m {
			case 0x00:
				result = append(result, socksfern.SocksAuthMethodNoAuth)
			case 0x01:
				result = append(result, socksfern.SocksAuthMethodGssapi)
			case 0x02:
				result = append(result, socksfern.SocksAuthMethodUsernamePassword)
			default:
				result = append(result, socksfern.SocksAuthMethodUnknown)
			}
		}
	}

	return result
}
