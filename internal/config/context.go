package config

import (
	"context"
)

type proxyConfigContextKey struct{}

// ProxyConfig stores proxy settings that are shared by subcommands through context.
type ProxyConfig struct {
	SocksProxy string
}

// SetProxyConfig returns a context with proxy settings attached.
func SetProxyConfig(ctx context.Context, socksProxy string) context.Context {
	return context.WithValue(ctx, proxyConfigContextKey{}, ProxyConfig{SocksProxy: socksProxy})
}

// ProxyConfigFromContext returns proxy settings from ctx, if present.
func ProxyConfigFromContext(ctx context.Context) ProxyConfig {
	cfg, ok := ctx.Value(proxyConfigContextKey{}).(ProxyConfig)
	if !ok {
		return ProxyConfig{}
	}
	return cfg
}
