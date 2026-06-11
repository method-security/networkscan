package discover

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

func TestValidatePortScanSeparatesPortAndPluginConcurrency(t *testing.T) {
	original := runServiceFingerprintForValidation
	defer func() { runServiceFingerprintForValidation = original }()

	validateThreads := 2
	validatePluginThreads := 3
	timeout := 7

	var mu sync.Mutex
	active := 0
	maxActive := 0
	seenConfigs := make([]discoverfern.DiscoverServiceConfig, 0)

	runServiceFingerprintForValidation = func(ctx context.Context, config discoverfern.DiscoverServiceConfig) (*discoverfern.DiscoverServiceReport, error) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		seenConfigs = append(seenConfigs, config)
		mu.Unlock()

		time.Sleep(25 * time.Millisecond)

		mu.Lock()
		active--
		mu.Unlock()

		return &discoverfern.DiscoverServiceReport{
			Config: &config,
			Result: &discoverfern.DiscoverServiceResult{
				Services: []*discoverfern.ServiceDetails{
					{
						Host:      "127.0.0.1",
						Ip:        "127.0.0.1",
						Port:      portFromTarget(config.Target),
						Transport: common.TransportTypeTcp,
						Protocol:  common.ProtocolTypeSsh,
					},
				},
			},
		}, nil
	}

	ports := []*discoverfern.PortDetails{
		{Port: 22, Protocol: common.TransportTypeTcp},
		{Port: 80, Protocol: common.TransportTypeTcp},
		{Port: 443, Protocol: common.TransportTypeTcp},
		{Port: 8080, Protocol: common.TransportTypeTcp},
		{Port: 8443, Protocol: common.TransportTypeTcp},
	}
	sockets := []*discoverfern.SocketDetails{
		{Host: "localhost", Ip: "127.0.0.1", Ports: ports},
	}

	validated, errors := validatePortScan(context.Background(), discoverfern.DiscoverPortConfig{
		ValidateThreads:        &validateThreads,
		ValidatePluginThreads:  validatePluginThreads,
		ValidateAttemptTimeout: &timeout,
	}, sockets)
	if len(errors) != 0 {
		t.Fatalf("expected no validation errors, got %v", errors)
	}
	if len(validated) != 1 || len(validated[0].Ports) != len(ports) {
		t.Fatalf("expected all ports to validate, got %#v", validated)
	}
	if maxActive > validateThreads {
		t.Fatalf("expected at most %d ports validated concurrently, got %d", validateThreads, maxActive)
	}
	if maxActive != validateThreads {
		t.Fatalf("expected validateThreads to control port concurrency, got max %d", maxActive)
	}
	if len(seenConfigs) != len(ports) {
		t.Fatalf("expected %d service fingerprint calls, got %d", len(ports), len(seenConfigs))
	}
	for _, config := range seenConfigs {
		if config.Threads != validatePluginThreads {
			t.Fatalf("expected service plugin threads %d, got %d", validatePluginThreads, config.Threads)
		}
		if config.Timeout != timeout {
			t.Fatalf("expected timeout %d, got %d", timeout, config.Timeout)
		}
	}
}

func portFromTarget(target string) int {
	var port int
	_, _ = fmt.Sscanf(target, "127.0.0.1:%d", &port)
	return port
}
