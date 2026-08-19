package service_test

import (
	"testing"

	service "github.com/Method-Security/networkscan/internal/discover/service"
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

func TestFxProtocolToProtocolTypeRejectsUnknown(t *testing.T) {
	if _, err := service.FxProtocolToProtocolType("NOTAPROTOCOL"); err == nil {
		t.Error("FxProtocolToProtocolType(\"NOTAPROTOCOL\") = nil error, want error")
	}
}
