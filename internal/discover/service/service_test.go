package service

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
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

type blockingFingerprinter struct {
	started chan<- string
	release <-chan struct{}
}

func (b *blockingFingerprinter) Name() string {
	return "blocking"
}

func (b *blockingFingerprinter) DefaultPorts() []int {
	return nil
}

func (b *blockingFingerprinter) Detect(ctx context.Context, ip net.IP, port int, _ string, _ int) (*discoverfern.ServiceDetails, error) {
	select {
	case b.started <- fmt.Sprintf("%s:%d", ip, port):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	select {
	case <-b.release:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type timeoutFingerprinter struct{}

func (t *timeoutFingerprinter) Name() string {
	return "timeout"
}

func (t *timeoutFingerprinter) DefaultPorts() []int {
	return nil
}

func (t *timeoutFingerprinter) Detect(ctx context.Context, _ net.IP, _ int, _ string, _ int) (*discoverfern.ServiceDetails, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type resultFingerprinter struct{}

func (r *resultFingerprinter) Name() string {
	return "result"
}

func (r *resultFingerprinter) DefaultPorts() []int {
	return nil
}

func (r *resultFingerprinter) Detect(_ context.Context, _ net.IP, port int, _ string, _ int) (*discoverfern.ServiceDetails, error) {
	return &discoverfern.ServiceDetails{Port: port}, nil
}

type stubbornFingerprinter struct {
	release <-chan struct{}
}

func (s *stubbornFingerprinter) Name() string {
	return "stubborn"
}

func (s *stubbornFingerprinter) DefaultPorts() []int {
	return nil
}

func (s *stubbornFingerprinter) Detect(_ context.Context, _ net.IP, _ int, _ string, _ int) (*discoverfern.ServiceDetails, error) {
	<-s.release
	return nil, nil
}

func TestRunFingerprintersParallelTimeoutIsPerPlugin(t *testing.T) {
	detection := runFingerprintersParallel(
		context.Background(),
		[]Fingerprinter{&timeoutFingerprinter{}, &resultFingerprinter{}},
		net.ParseIP("10.0.0.1"),
		443,
		"10.0.0.1",
		1,
		1,
	)

	if detection == nil || detection.Port != 443 {
		t.Fatalf("detection = %#v, want queued plugin result", detection)
	}
}

func TestRunFingerprintersParallelTimeoutDoesNotBlockOnStubbornPlugin(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	start := time.Now()
	detection := runFingerprintersParallel(
		context.Background(),
		[]Fingerprinter{&stubbornFingerprinter{release: release}, &resultFingerprinter{}},
		net.ParseIP("10.0.0.1"),
		443,
		"10.0.0.1",
		1,
		1,
	)

	if detection == nil || detection.Port != 443 {
		t.Fatalf("detection = %#v, want queued plugin result", detection)
	}
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Fatalf("elapsed = %s, want stubborn plugin timeout to release worker", elapsed)
	}
}

func TestParseServiceTargetsUsesPerIPHostForExpandedTargets(t *testing.T) {
	targets, err := parseServiceTargets("10.0.0.0/30")
	if err != nil {
		t.Fatalf("parseServiceTargets returned error: %v", err)
	}

	if len(targets) != 4 {
		t.Fatalf("target count = %d, want 4", len(targets))
	}
	for _, target := range targets {
		if target.host != target.ip.String() {
			t.Fatalf("target host = %q for ip %q, want per-IP host", target.host, target.ip)
		}
	}
}

func TestParseTCPServiceTargetsSupportsMultiplePorts(t *testing.T) {
	targets, err := parseTCPServiceTargets([]string{"10.0.0.1:22", "10.0.0.4/30:443"})
	if err != nil {
		t.Fatalf("parseTCPServiceTargets returned error: %v", err)
	}

	if len(targets) != 5 {
		t.Fatalf("target count = %d, want 5", len(targets))
	}
	if targets[0].host != "10.0.0.1" || targets[0].port != 22 {
		t.Fatalf("first target = %#v, want 10.0.0.1:22", targets[0])
	}
	for _, target := range targets[1:] {
		if target.port != 443 {
			t.Fatalf("expanded target port = %d, want 443", target.port)
		}
		if target.host != target.ip.String() {
			t.Fatalf("expanded target host = %q for ip %q, want per-IP host", target.host, target.ip)
		}
	}
}

func TestRunUDPServiceDiscoveryThreadsTargetsAndPlugins(t *testing.T) {
	originalFingerprinters := udpFingerprinters
	defer func() { udpFingerprinters = originalFingerprinters }()

	started := make(chan string, 4)
	release := make(chan struct{})
	fingerprinter := &blockingFingerprinter{started: started, release: release}
	udpFingerprinters = map[uint16]Fingerprinter{
		53:  fingerprinter,
		123: fingerprinter,
	}

	udp := true
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = runUDPServiceDiscovery(context.Background(), discoverfern.DiscoverServiceConfig{
			Targets: []string{"10.0.0.0/30"},
			Timeout: -1,
			Threads: 2,
			Udp:     &udp,
		})
	}()

	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("received %d of 4 concurrent starts", i)
		}
	}

	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UDP discovery did not complete after releasing probes")
	}
}

func TestRunUDPServiceDiscoveryCollectsEveryDetection(t *testing.T) {
	originalFingerprinters := udpFingerprinters
	defer func() { udpFingerprinters = originalFingerprinters }()

	udpFingerprinters = make(map[uint16]Fingerprinter, 64)
	for port := uint16(1); port <= 64; port++ {
		udpFingerprinters[port] = &resultFingerprinter{}
	}

	results := runUDPServiceDiscoveryForIP(context.Background(), discoverfern.DiscoverServiceConfig{
		Timeout: 1,
		Threads: 64,
	}, net.ParseIP("10.0.0.1"))

	if len(results) != len(udpFingerprinters) {
		t.Fatalf("result count = %d, want %d", len(results), len(udpFingerprinters))
	}
}

func TestRunUDPServiceDiscoveryTimeoutDoesNotBlockOnStubbornPlugin(t *testing.T) {
	originalFingerprinters := udpFingerprinters
	defer func() { udpFingerprinters = originalFingerprinters }()

	release := make(chan struct{})
	defer close(release)
	udpFingerprinters = map[uint16]Fingerprinter{
		53:  &stubbornFingerprinter{release: release},
		123: &resultFingerprinter{},
	}

	start := time.Now()
	results := runUDPServiceDiscoveryForIP(context.Background(), discoverfern.DiscoverServiceConfig{
		Timeout: 1,
		Threads: 1,
	}, net.ParseIP("10.0.0.1"))

	if len(results) != 1 || results[0].Port != 123 {
		t.Fatalf("results = %#v, want UDP result after stubborn plugin timeout", results)
	}
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Fatalf("elapsed = %s, want stubborn UDP plugin timeout to release worker", elapsed)
	}
}
