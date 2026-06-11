package cmd

import (
	"testing"

	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

func TestGetDiscoverServiceConfigNormalizesCustomPluginThreads(t *testing.T) {
	config, err := getDiscoverServiceConfig("127.0.0.1:80", defaultServiceFingerprintTimeout, "", false, 0)
	if err != nil {
		t.Fatalf("getDiscoverServiceConfig returned error: %v", err)
	}
	if config.Timeout != defaultServiceFingerprintTimeout {
		t.Fatalf("expected timeout %d, got %d", defaultServiceFingerprintTimeout, config.Timeout)
	}
	if config.Threads != defaultCustomPluginThreads {
		t.Fatalf("expected custom plugin threads %d, got %d", defaultCustomPluginThreads, config.Threads)
	}
}

func TestGetDiscoverPortConfigNormalizesValidatePluginThreads(t *testing.T) {
	config := getDiscoverPortConfig(
		"127.0.0.1",
		"80",
		"",
		25,
		1000,
		discoverfern.PortScanTypeConnect,
		true,
		nil,
		nil,
		0,
		nil,
		0,
		0,
	)
	if config.ValidatePluginThreads != defaultCustomPluginThreads {
		t.Fatalf("expected validate plugin threads %d, got %d", defaultCustomPluginThreads, config.ValidatePluginThreads)
	}
}
