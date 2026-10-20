package helpers

import (
	"context"
	"testing"
)

func TestHTTPUserAgentScope(t *testing.T) {
	parent := context.Background()
	chrome := WithHTTPUserAgent(parent, "chrome-fixture")
	curl := WithHTTPUserAgent(parent, "curl-fixture")
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"default", parent, ""},
		{"chrome", chrome, "chrome-fixture"},
		{"curl", curl, "curl-fixture"},
		{"empty", WithHTTPUserAgent(parent, ""), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := HTTPUserAgent(tc.ctx); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
