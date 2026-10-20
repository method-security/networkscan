package helpers

import (
	"context"
)

type httpUserAgentKey struct{}

// WithHTTPUserAgent scopes an explicit HTTP header override to one scan. Other
// protocol probes do not read it, and concurrent scans cannot overwrite it.
func WithHTTPUserAgent(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, httpUserAgentKey{}, value)
}

// HTTPUserAgent returns the explicit override, or empty to leave transport defaults intact.
func HTTPUserAgent(ctx context.Context) string {
	value, _ := ctx.Value(httpUserAgentKey{}).(string)
	return value
}
