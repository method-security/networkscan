package netdial

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/Method-Security/networkscan/internal/config"
	"golang.org/x/net/proxy"
)

// Options configures outbound TCP dials.
type Options struct {
	Timeout  time.Duration
	Deadline time.Time
}

// Option mutates dial options.
type Option func(*Options)

// WithTimeout sets the connection timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(o *Options) {
		o.Timeout = timeout
	}
}

// WithDeadline sets the absolute dial deadline.
func WithDeadline(deadline time.Time) Option {
	return func(o *Options) {
		o.Deadline = deadline
	}
}

// DialContext dials directly unless ctx carries a SOCKS proxy and network is TCP.
func DialContext(ctx context.Context, network, address string, opts ...Option) (net.Conn, error) {
	options := Options{}
	for _, opt := range opts {
		opt(&options)
	}

	dialer := &net.Dialer{
		Timeout:  options.Timeout,
		Deadline: options.Deadline,
	}

	proxyConfig := config.ProxyConfigFromContext(ctx)
	if proxyConfig.SocksProxy == "" || !isTCPNetwork(network) {
		return dialer.DialContext(ctx, network, address)
	}

	proxyURL, err := url.Parse(proxyConfig.SocksProxy)
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS proxy URL: %w", err)
	}
	if proxyURL.Scheme != "socks5" && proxyURL.Scheme != "socks5h" {
		return nil, fmt.Errorf("unsupported SOCKS proxy scheme %q", proxyURL.Scheme)
	}

	socksDialer, err := proxy.FromURL(proxyURL, dialer)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS proxy dialer: %w", err)
	}
	contextDialer, ok := socksDialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("SOCKS proxy dialer does not support context-aware dialing")
	}
	return contextDialer.DialContext(ctx, network, address)
}

func isTCPNetwork(network string) bool {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}
