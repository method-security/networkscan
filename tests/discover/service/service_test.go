package service_test

import (
	"testing"

	service "github.com/Method-Security/networkscan/internal/discover/service"
)

func TestFxProtocolToProtocolTypeAliases(t *testing.T) {
	cases := map[string]string{
		"oracle":     "ORACLEDB",
		"postgres":   "POSTGRESQL",
		"netbios-ns": "NETBIOS",
		"kafkaNew":   "KAFKA",
		"ssh":        "SSH",
	}

	for name, want := range cases {
		got, err := service.FxProtocolToProtocolType(name)
		if err != nil {
			t.Errorf("FxProtocolToProtocolType(%q): %v", name, err)
			continue
		}
		if string(got) != want {
			t.Errorf("FxProtocolToProtocolType(%q) = %q, want %q", name, got, want)
		}
	}
}

// "ipsec" is fingerprintx's UDP-500 probe, deliberately unsupported: our own ike plugin owns that port.
func TestFxProtocolToProtocolTypeRejectsUnknown(t *testing.T) {
	for _, name := range []string{"NOTAPROTOCOL", "ipsec"} {
		if _, err := service.FxProtocolToProtocolType(name); err == nil {
			t.Errorf("FxProtocolToProtocolType(%q) = nil error, want error", name)
		}
	}
}
