package utils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
)

// NetErrorCategory is a stable, coarse classification of a failed outbound
// connection/probe. It is the closest thing to an "error code" an operator can
// filter and triage on when a scan never reaches the target — the common shape
// when egress is blocked by a firewall or routed through a restricted network.
type NetErrorCategory string

const (
	NetErrorDNS           NetErrorCategory = "dns_resolution_failed"
	NetErrorConnRefused   NetErrorCategory = "connection_refused"
	NetErrorConnReset     NetErrorCategory = "connection_reset"
	NetErrorTimeout       NetErrorCategory = "timeout"
	NetErrorTLS           NetErrorCategory = "tls_error"
	NetErrorNoRouteToHost NetErrorCategory = "no_route_to_host"
	NetErrorNetworkDown   NetErrorCategory = "network_unreachable"
	NetErrorCanceled      NetErrorCategory = "canceled"
	NetErrorOther         NetErrorCategory = "network_error"
)

// NetErrorDetail is an operator-facing description of a failed connection. Cause
// is always the fully unwrapped error string (never a reflected struct), and the
// remaining fields name the layer that failed.
type NetErrorDetail struct {
	Category NetErrorCategory
	Cause    string
	Op       string
	Network  string
	Address  string
}

// String renders the detail as a single human-readable line.
func (d NetErrorDetail) String() string {
	var b strings.Builder
	b.WriteString(string(d.Category))
	if d.Address != "" {
		fmt.Fprintf(&b, " (%s", d.Address)
		if d.Network != "" {
			fmt.Fprintf(&b, "/%s", d.Network)
		}
		b.WriteString(")")
	}
	if d.Cause != "" {
		fmt.Fprintf(&b, ": %s", d.Cause)
	}
	return b.String()
}

// ClassifyNetError unwraps a Go network error (typically *net.OpError wrapping
// *net.DNSError / x509 / tls / syscall errors, possibly nested in *url.Error)
// into a stable category plus the underlying cause and the failing layer, so a
// probe that never reaches the target reports *why* (dns/refused/reset/no-route/
// tls/timeout) instead of an opaque struct dump.
func ClassifyNetError(err error) NetErrorDetail {
	if err == nil {
		return NetErrorDetail{}
	}
	detail := NetErrorDetail{Category: NetErrorOther, Cause: err.Error()}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		detail.Op = opErr.Op
		detail.Network = opErr.Net
		if opErr.Addr != nil {
			detail.Address = opErr.Addr.String()
		}
	}

	switch {
	case errors.Is(err, context.Canceled):
		detail.Category = NetErrorCanceled
	case errors.Is(err, context.DeadlineExceeded):
		detail.Category = NetErrorTimeout
	case classifyDNS(err, &detail):
		detail.Category = NetErrorDNS
	case classifyTLS(err):
		detail.Category = NetErrorTLS
	case classifySyscall(err, &detail):
		// category set by classifySyscall
	case isTimeout(err):
		detail.Category = NetErrorTimeout
	}
	return detail
}

func classifyDNS(err error, detail *NetErrorDetail) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.Name != "" {
			detail.Address = dnsErr.Name
		}
		return true
	}
	return false
}

func classifyTLS(err error) bool {
	var (
		unknownAuthority x509.UnknownAuthorityError
		hostnameErr      x509.HostnameError
		invalidCert      x509.CertificateInvalidError
		certVerifyErr    *tls.CertificateVerificationError
		recordHeaderErr  *tls.RecordHeaderError
	)
	if errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &invalidCert) ||
		errors.As(err, &certVerifyErr) ||
		errors.As(err, &recordHeaderErr) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "tls:") || strings.Contains(msg, "x509:")
}

func classifySyscall(err error, detail *NetErrorDetail) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case syscall.ECONNREFUSED:
		detail.Category = NetErrorConnRefused
	case syscall.ECONNRESET, syscall.EPIPE:
		detail.Category = NetErrorConnReset
	case syscall.EHOSTUNREACH:
		detail.Category = NetErrorNoRouteToHost
	case syscall.ENETUNREACH, syscall.ENETDOWN:
		detail.Category = NetErrorNetworkDown
	case syscall.ETIMEDOUT:
		detail.Category = NetErrorTimeout
	default:
		return false
	}
	return true
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
