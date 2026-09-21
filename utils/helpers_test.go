package utils

import (
	"testing"
)

func TestParseTargetHostsIncludesCIDREndpoints(t *testing.T) {
	hosts, err := ParseTargetHosts("192.0.2.0/28")
	if err != nil {
		t.Fatalf("ParseTargetHosts returned error: %v", err)
	}

	if len(hosts) != 16 {
		t.Fatalf("host count = %d, want 16", len(hosts))
	}
	if hosts[0] != "192.0.2.0" {
		t.Fatalf("first host = %q, want %q", hosts[0], "192.0.2.0")
	}
	if hosts[len(hosts)-1] != "192.0.2.15" {
		t.Fatalf("last host = %q, want %q", hosts[len(hosts)-1], "192.0.2.15")
	}
}

func TestResolveLDAPTarget(t *testing.T) {
	cases := []struct {
		target string
		host   string
		port   int
		useTLS bool
	}{
		// A scheme states the transport, so it wins over the port.
		{"ldaps://10.0.0.1:1636", "10.0.0.1", 1636, true},
		{"ldap://10.0.0.1:636", "10.0.0.1", 636, false},
		{"LDAPS://10.0.0.1:389", "10.0.0.1", 389, true},
		{"ldaps://dc01.corp.local", "dc01.corp.local", 389, true},
		// Bare targets fall back to the implicit-TLS ports.
		{"10.0.0.1:389", "10.0.0.1", 389, false},
		{"10.0.0.1:636", "10.0.0.1", 636, true},
		{"10.0.0.1:3269", "10.0.0.1", 3269, true},
		{"10.0.0.1:3268", "10.0.0.1", 3268, false},
		{"10.0.0.1:1636", "10.0.0.1", 1636, false},
		{"10.0.0.1", "10.0.0.1", 389, false},
	}

	for _, tc := range cases {
		host, port, useTLS := ResolveLDAPTarget(tc.target)
		if host != tc.host {
			t.Errorf("ResolveLDAPTarget(%q) host = %q, want %q", tc.target, host, tc.host)
		}
		if port != tc.port {
			t.Errorf("ResolveLDAPTarget(%q) port = %d, want %d", tc.target, port, tc.port)
		}
		if useTLS != tc.useTLS {
			t.Errorf("ResolveLDAPTarget(%q) useTLS = %v, want %v", tc.target, useTLS, tc.useTLS)
		}
	}
}

func TestResolveLDAPTargetFeedsFormatLDAPURL(t *testing.T) {
	cases := []struct {
		target string
		want   string
	}{
		{"ldaps://10.0.0.1:636", "ldaps://10.0.0.1:636"},
		{"10.0.0.1:636", "ldaps://10.0.0.1:636"},
		{"10.0.0.1:3269", "ldaps://10.0.0.1:3269"},
		{"10.0.0.1:389", "ldap://10.0.0.1:389"},
		{"ldap://10.0.0.1:636", "ldap://10.0.0.1:636"},
	}

	for _, tc := range cases {
		host, port, useTLS := ResolveLDAPTarget(tc.target)
		if got := FormatLDAPURL(host, port, useTLS); got != tc.want {
			t.Errorf("dial URL for %q = %q, want %q", tc.target, got, tc.want)
		}
	}
}
