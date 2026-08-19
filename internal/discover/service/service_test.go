package service

import (
	"testing"
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
		got, err := fxProtocolToProtocolType(name)
		if err != nil {
			t.Errorf("fxProtocolToProtocolType(%q): %v", name, err)
			continue
		}
		if string(got) != want {
			t.Errorf("fxProtocolToProtocolType(%q) = %q, want %q", name, got, want)
		}
	}
}

// "ipsec" is fingerprintx's UDP-500 probe, deliberately unsupported: our own ike plugin owns that port.
func TestFxProtocolToProtocolTypeRejectsUnknown(t *testing.T) {
	for _, name := range []string{"NOTAPROTOCOL", "ipsec"} {
		if _, err := fxProtocolToProtocolType(name); err == nil {
			t.Errorf("fxProtocolToProtocolType(%q) = nil error, want error", name)
		}
	}
}
