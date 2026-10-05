package discover

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

func TestValidatePortScanKeepsHTTPBlockingResponse(t *testing.T) {
	originalRunServiceFingerprint := runServiceFingerprintForValidation
	defer func() { runServiceFingerprintForValidation = originalRunServiceFingerprint }()

	runServiceFingerprintForValidation = func(_ context.Context, _ discoverfern.DiscoverServiceConfig) (*discoverfern.DiscoverServiceReport, error) {
		return &discoverfern.DiscoverServiceReport{
			Result: &discoverfern.DiscoverServiceResult{
				Services: []*discoverfern.ServiceDetails{{
					Protocol: common.ProtocolTypeHttp,
					Metadata: &discoverfern.ServiceMetadata{Generic: &discoverfern.GenericServiceMetadata{
						Metadata: map[string]string{"status": "403 Forbidden"},
					}},
				}},
			},
		}, nil
	}

	validated, errors := validatePortScan(context.Background(), discoverfern.DiscoverPortConfig{}, []*discoverfern.SocketDetails{
		{Ip: "10.0.0.1", Ports: []*discoverfern.PortDetails{{Port: 80}}},
	})
	if len(errors) != 0 {
		t.Fatalf("validation errors = %v, want none", errors)
	}
	if len(validated) != 1 || len(validated[0].Ports) != 1 || validated[0].Ports[0].Port != 80 {
		t.Fatalf("validated sockets = %v, want port 80 retained", validated)
	}
}

func TestValidatePortScanThreadsAcrossSockets(t *testing.T) {
	originalRunServiceFingerprint := runServiceFingerprintForValidation
	defer func() { runServiceFingerprintForValidation = originalRunServiceFingerprint }()

	var active int32
	var maxActive int32
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	runServiceFingerprintForValidation = func(ctx context.Context, _ discoverfern.DiscoverServiceConfig) (*discoverfern.DiscoverServiceReport, error) {
		current := atomic.AddInt32(&active, 1)
		for {
			max := atomic.LoadInt32(&maxActive)
			if current <= max || atomic.CompareAndSwapInt32(&maxActive, max, current) {
				break
			}
		}
		defer atomic.AddInt32(&active, -1)

		select {
		case started <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		return &discoverfern.DiscoverServiceReport{
			Result: &discoverfern.DiscoverServiceResult{
				Services: []*discoverfern.ServiceDetails{{}},
			},
		}, nil
	}

	validateThreads := 2
	validateAttemptTimeout := 1
	done := make(chan []*discoverfern.SocketDetails)
	go func() {
		validated, _ := validatePortScan(context.Background(), discoverfern.DiscoverPortConfig{
			ValidateThreads:        &validateThreads,
			ValidateAttemptTimeout: &validateAttemptTimeout,
		}, []*discoverfern.SocketDetails{
			{Ip: "10.0.0.1", Ports: []*discoverfern.PortDetails{{Port: 80}}},
			{Ip: "10.0.0.2", Ports: []*discoverfern.PortDetails{{Port: 443}}},
		})
		done <- validated
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("received %d of 2 concurrent validation starts", i)
		}
	}

	close(release)
	select {
	case validated := <-done:
		if len(validated) != 2 {
			t.Fatalf("validated socket count = %d, want 2", len(validated))
		}
	case <-time.After(time.Second):
		t.Fatal("validation did not complete after releasing probes")
	}

	if got := atomic.LoadInt32(&maxActive); got != 2 {
		t.Fatalf("max concurrent validations = %d, want 2", got)
	}
}

func TestValidateTriggeredPortScanScopesValidationToTriggeredIP(t *testing.T) {
	originalRunServiceFingerprint := runServiceFingerprintForValidation
	defer func() { runServiceFingerprintForValidation = originalRunServiceFingerprint }()

	var targets []string
	runServiceFingerprintForValidation = func(_ context.Context, config discoverfern.DiscoverServiceConfig) (*discoverfern.DiscoverServiceReport, error) {
		targets = append(targets, config.Targets[0])
		services := []*discoverfern.ServiceDetails{}
		if config.Targets[0] == "10.0.0.1:80" {
			services = []*discoverfern.ServiceDetails{{}}
		}
		return &discoverfern.DiscoverServiceReport{
			Result: &discoverfern.DiscoverServiceResult{Services: services},
		}, nil
	}

	validateThreads := 1
	validateAttemptTimeout := 1
	threshold := 1
	validated, _ := validateTriggeredPortScan(context.Background(), discoverfern.DiscoverPortConfig{
		ValidateThreads:                 &validateThreads,
		ValidateAttemptTimeout:          &validateAttemptTimeout,
		MaxOpenPortsValidationThreshold: &threshold,
	}, []*discoverfern.SocketDetails{
		{Ip: "10.0.0.1", Ports: []*discoverfern.PortDetails{{Port: 80}, {Port: 81}}},
		{Ip: "10.0.0.2", Ports: []*discoverfern.PortDetails{{Port: 443}}},
	})

	if !reflect.DeepEqual(targets, []string{"10.0.0.1:80", "10.0.0.1:81"}) {
		t.Fatalf("validation targets = %v, want only triggered IP ports", targets)
	}
	if len(validated) != 2 {
		t.Fatalf("validated socket count = %d, want 2", len(validated))
	}
	if got := validated[0].Ports; len(got) != 1 || got[0].Port != 80 {
		t.Fatalf("validated ports for triggered IP = %v, want only port 80", got)
	}
	if got := validated[1].Ports; len(got) != 1 || got[0].Port != 443 {
		t.Fatalf("ports for untriggered IP = %v, want untouched port 443", got)
	}
}
