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

func HTTPUserAgent(ctx context.Context, fallback string) string {
	if value, ok := ctx.Value(httpUserAgentKey{}).(string); ok && value != "" {
		return value
	}
	return fallback
}
