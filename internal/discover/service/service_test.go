package service

import (
	"testing"
)

func TestFxProtocolToProtocolTypeAliases(t *testing.T) {
	cases := map[string]string{
		"IPsec":      "IKE",
		"ipsec":      "IKE",
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
