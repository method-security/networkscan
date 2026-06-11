package service

import (
	"context"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

type testFingerprinter struct {
	name         string
	defaultPorts []int
	delay        time.Duration
	result       *discoverfern.ServiceDetails
	onDetect     func()
}

func (t *testFingerprinter) Name() string { return t.name }

func (t *testFingerprinter) DefaultPorts() []int { return t.defaultPorts }

func (t *testFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	if t.onDetect != nil {
		t.onDetect()
	}
	if t.delay > 0 {
		timer := time.NewTimer(t.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return t.result, nil
}

func TestRunFingerprintersParallelLimitsConcurrency(t *testing.T) {
	var active atomic.Int32
	var maxActive atomic.Int32
	var calls atomic.Int32

	trackDetect := func() {
		calls.Add(1)
		current := active.Add(1)
		defer active.Add(-1)
		for {
			previous := maxActive.Load()
			if current <= previous || maxActive.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}

	fingerprinters := make([]Fingerprinter, 10)
	for i := range fingerprinters {
		fingerprinters[i] = &testFingerprinter{name: "fp", onDetect: trackDetect}
	}

	result := runFingerprintersParallel(context.Background(), fingerprinters, net.ParseIP("127.0.0.1"), 8080, "127.0.0.1", 2, 3)
	if result != nil {
		t.Fatalf("expected no detection, got %#v", result)
	}
	if got := maxActive.Load(); got > 3 {
		t.Fatalf("expected at most 3 concurrent Detect calls, got %d", got)
	}
	if got := calls.Load(); got != int32(len(fingerprinters)) {
		t.Fatalf("expected all fingerprinters to run, got %d", got)
	}
}

func TestRunFingerprintersParallelPreservesRegistryPriority(t *testing.T) {
	highPriority := &discoverfern.ServiceDetails{
		Host:      "127.0.0.1",
		Ip:        "127.0.0.1",
		Port:      8080,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeSsh,
	}
	lowPriority := &discoverfern.ServiceDetails{
		Host:      "127.0.0.1",
		Ip:        "127.0.0.1",
		Port:      8080,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeHttp,
	}

	result := runFingerprintersParallel(
		context.Background(),
		[]Fingerprinter{
			&testFingerprinter{name: "high", delay: 60 * time.Millisecond, result: highPriority},
			&testFingerprinter{name: "low", result: lowPriority},
		},
		net.ParseIP("127.0.0.1"),
		8080,
		"127.0.0.1",
		2,
		2,
	)
	if result == nil {
		t.Fatal("expected a detection")
	}
	if result.Protocol != common.ProtocolTypeSsh {
		t.Fatalf("expected earlier registry match to win, got %s", result.Protocol)
	}
}

func TestRunServiceFingerprintUDPUsesOnlyUDPFingerprinters(t *testing.T) {
	originalUDP := udpFingerprinters
	originalTCP := customFingerprintModules
	defer func() {
		udpFingerprinters = originalUDP
		customFingerprintModules = originalTCP
	}()

	var udpCalls atomic.Int32
	var tcpCalls atomic.Int32
	udpFingerprinters = map[uint16]Fingerprinter{
		65000: &testFingerprinter{
			name: "udp",
			result: &discoverfern.ServiceDetails{
				Host:      "127.0.0.1",
				Ip:        "127.0.0.1",
				Port:      65000,
				Transport: common.TransportTypeUdp,
				Protocol:  common.ProtocolTypeDns,
			},
			onDetect: func() { udpCalls.Add(1) },
		},
	}
	customFingerprintModules = []Fingerprinter{
		&testFingerprinter{
			name:         "tcp",
			defaultPorts: []int{65000},
			result: &discoverfern.ServiceDetails{
				Host:      "127.0.0.1",
				Ip:        "127.0.0.1",
				Port:      65000,
				Transport: common.TransportTypeTcp,
				Protocol:  common.ProtocolTypeHttp,
			},
			onDetect: func() { tcpCalls.Add(1) },
		},
	}

	udp := true
	report, err := RunServiceFingerprint(context.Background(), discoverfern.DiscoverServiceConfig{
		Target:  "127.0.0.1:65000",
		Timeout: 1,
		Threads: 8,
		Udp:     &udp,
	})
	if err != nil {
		t.Fatalf("RunServiceFingerprint returned error: %v", err)
	}
	if udpCalls.Load() != 1 {
		t.Fatalf("expected UDP fingerprinter to run once, got %d", udpCalls.Load())
	}
	if tcpCalls.Load() != 0 {
		t.Fatalf("expected TCP custom fingerprinter not to run in UDP mode, got %d calls", tcpCalls.Load())
	}
	if report == nil || report.Result == nil || len(report.Result.Services) == 0 {
		t.Fatal("expected UDP service result")
	}
}

func TestFingerprintxConfigAndUDPPathSourceChecks(t *testing.T) {
	sourceBytes, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("read service.go: %v", err)
	}
	source := string(sourceBytes)

	tcpBody := functionBody(t, source, "RunServiceFingerprint")
	for _, expected := range []string{
		"FastMode:       false",
		"DefaultTimeout: servicehelpers.Timeout(config.Timeout)",
		"UDP:            false",
		"SimpleScanTarget",
		"config.Threads",
	} {
		if !strings.Contains(tcpBody, expected) {
			t.Fatalf("RunServiceFingerprint missing %q", expected)
		}
	}

	udpBody := functionBody(t, source, "runUDPServiceDiscovery")
	for _, expected := range []string{
		"udpFingerprinters",
		"UDPScanTarget",
		"UDP:            true",
		"DefaultTimeout: servicehelpers.Timeout(config.Timeout)",
	} {
		if !strings.Contains(udpBody, expected) {
			t.Fatalf("runUDPServiceDiscovery missing %q", expected)
		}
	}
	for _, staleTCPPath := range []string{"customFingerprintModules", "SimpleScanTarget"} {
		if strings.Contains(udpBody, staleTCPPath) {
			t.Fatalf("runUDPServiceDiscovery should not reference %q", staleTCPPath)
		}
	}
}

func functionBody(t *testing.T, source string, name string) string {
	t.Helper()
	start := strings.Index(source, "func "+name+"(")
	if start < 0 {
		t.Fatalf("function %s not found", name)
	}
	open := strings.Index(source[start:], "{")
	if open < 0 {
		t.Fatalf("function %s body not found", name)
	}
	i := start + open
	depth := 0
	for ; i < len(source); i++ {
		switch source[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return source[start : i+1]
			}
		}
	}
	t.Fatalf("function %s body did not close", name)
	return ""
}
