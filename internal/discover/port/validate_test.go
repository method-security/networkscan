package discover

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

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
			{Ip: "192.0.2.1", Ports: []*discoverfern.PortDetails{{Port: 80}}},
			{Ip: "192.0.2.2", Ports: []*discoverfern.PortDetails{{Port: 443}}},
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
