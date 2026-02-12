// Package discover implements network discovery functionality for finding live hosts and services.
package discover

import (
	// Standard
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/labstack/gommon/log"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// tracer defines the interface for different traceroute probe implementations.
// Each implementation handles a specific probe type (ICMP, UDP, TCP).
type tracer interface {
	SendProbe(ttl int, timeout time.Duration) (string, error)
	Close() error
}

// icmpTracer implements traceroute using ICMP Echo Request packets.
// It requires raw socket privileges and measures RTT by sending echo requests
// and waiting for Time Exceeded or Echo Reply responses.
type icmpTracer struct {
	conn   *icmp.PacketConn
	destIP net.IP
	id     int
}

// udpTracer implements traceroute using UDP packets to high-numbered ports.
// It sends UDP packets and listens for ICMP Time Exceeded responses from intermediate hops.
type udpTracer struct {
	sendConn *net.UDPConn
	recvConn *icmp.PacketConn
	destIP   net.IP
	port     int
}

// RunRouteDiscovery performs network path tracing to discover the route packets take to reach targets.
// It uses various probe types (UDP, ICMP, TCP SYN) with incrementing TTL values to map network hops.
// Returns a detailed report containing hop information, RTT measurements, and any errors encountered.
func RunRouteDiscovery(ctx context.Context, config discoverfern.DiscoverRouteConfig) (*discoverfern.DiscoverRouteReport, error) {
	errors := []string{}

	log := svc1log.FromContext(ctx)

	// Get required configuration values
	maxHops := config.MaxHops
	timeout := time.Duration(config.Timeout) * time.Second
	probeType := config.ProbeType
	port := config.Port

	log.Info("Starting traceroute", svc1log.SafeParam("targets", config.Targets), svc1log.SafeParam("maxHops", maxHops), svc1log.SafeParam("probeType", probeType))

	var tracerouteResults []*discoverfern.TracerouteResult

	// Process each target
	for _, target := range config.Targets {
		log.Info("Processing target", svc1log.SafeParam("target", target))

		// Resolve target to IP
		log.Info("Resolving target hostname", svc1log.SafeParam("target", target))
		targetIP, err := resolveTarget(target)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to resolve target %s: %v", target, err))
			continue
		}
		log.Info("Target resolved", svc1log.SafeParam("target", target), svc1log.SafeParam("targetIP", targetIP))

		// Perform traceroute
		// Get configuration values (all required now)
		probesPerHop := config.ProbesPerHop
		probeDelay := config.ProbeDelay

		tracerouteResult, err := performTraceroute(ctx, target, targetIP, maxHops, timeout, probeType, port, probesPerHop, probeDelay)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Traceroute failed for %s: %v", target, err))
			continue
		}

		// Filter out timed out hops if requested
		if config.ExcludeTimeoutHops {
			var filteredHops []*discoverfern.TracerouteHop
			for _, hop := range tracerouteResult.Hops {
				if !hop.Timeout {
					filteredHops = append(filteredHops, hop)
				}
			}
			tracerouteResult.Hops = filteredHops
		}

		log.Info("Traceroute completed", svc1log.SafeParam("target", target), svc1log.SafeParam("hops", len(tracerouteResult.Hops)))
		tracerouteResults = append(tracerouteResults, tracerouteResult)
	}

	return &discoverfern.DiscoverRouteReport{
		Config: &config,
		Result: &discoverfern.DiscoverRouteResult{
			Traceroutes: tracerouteResults,
		},
		Errors: errors,
	}, nil
}

// resolveTarget converts a hostname to an IP address or validates an existing IP address.
// It prefers IPv4 addresses when multiple addresses are available.
func resolveTarget(target string) (string, error) {
	// Check if target is already an IP address
	if ip := net.ParseIP(target); ip != nil {
		return target, nil
	}

	// Resolve hostname to IP
	ips, err := net.LookupIP(target)
	if err != nil {
		return "", fmt.Errorf("failed to resolve hostname: %w", err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for hostname")
	}

	// Prefer IPv4 address
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}

	// Fall back to first IP (might be IPv6)
	return ips[0].String(), nil
}

// performTraceroute executes the actual traceroute operation using the specified probe type.
// It sends probes with incrementing TTL values and collects responses from intermediate hops.
func performTraceroute(ctx context.Context, target, targetIP string, maxHops int, timeout time.Duration, probeType discoverfern.ProbeType, port, probesPerHop, probeDelay int) (*discoverfern.TracerouteResult, error) {
	result := &discoverfern.TracerouteResult{
		Target:    target,
		TargetIp:  targetIP,
		MaxHops:   maxHops,
		Hops:      []*discoverfern.TracerouteHop{},
		Completed: false,
	}

	destIP := net.ParseIP(targetIP)
	if destIP == nil {
		return nil, fmt.Errorf("invalid target IP: %s", targetIP)
	}

	var tr tracer
	var err error

	log.Info("Initializing tracer", svc1log.SafeParam("probeType", probeType), svc1log.SafeParam("port", port))

	// Create appropriate tracer based on probe type
	switch probeType {
	case discoverfern.ProbeTypeIcmp:
		tr, err = newICMPTracer(destIP)
	case discoverfern.ProbeTypeUdp:
		tr, err = newUDPTracer(destIP, port)
	default:
		// TCP SYN is complex without raw sockets, fallback to UDP
		log.Info("TCP SYN not supported, falling back to UDP")
		tr, err = newUDPTracer(destIP, port)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create tracer: %w", err)
	}
	defer func() { _ = tr.Close() }()

	// Perform traceroute with increasing TTL
	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		hop := discoverfern.TracerouteHop{
			HopNumber: ttl,
			Timeout:   false,
		}

		// Send configurable number of probes per hop and measure RTT
		var wg sync.WaitGroup
		rtts := make([]float64, probesPerHop)
		timeouts := make([]bool, probesPerHop)
		var hopIP string
		var hopMutex sync.Mutex

		for i := 0; i < probesPerHop; i++ {
			wg.Add(1)
			go func(probeNum int) {
				defer wg.Done()

				start := time.Now()
				replyIP, err := tr.SendProbe(ttl, timeout)
				rtt := time.Since(start).Seconds() * 1000 // Convert to milliseconds

				hopMutex.Lock()
				defer hopMutex.Unlock()

				if err != nil {
					timeouts[probeNum] = true
				} else {
					rtts[probeNum] = rtt
					if hopIP == "" {
						hopIP = replyIP
					}
				}
			}(i)

			// Configurable delay between probes
			time.Sleep(time.Duration(probeDelay) * time.Millisecond)
		}

		wg.Wait()

		// Set IP address and try hostname resolution
		if hopIP != "" {
			hop.IpAddress = &hopIP
			if hostname, err := net.LookupAddr(hopIP); err == nil && len(hostname) > 0 {
				hop.Hostname = &hostname[0]
			}
		}

		// Set RTT values based on number of probes
		if probesPerHop >= 1 && !timeouts[0] {
			hop.Rtt1 = &rtts[0]
		}
		if probesPerHop >= 2 && !timeouts[1] {
			hop.Rtt2 = &rtts[1]
		}
		if probesPerHop >= 3 && !timeouts[2] {
			hop.Rtt3 = &rtts[2]
		}

		// Check if all probes timed out
		allTimeout := true
		for i := 0; i < probesPerHop; i++ {
			if !timeouts[i] {
				allTimeout = false
				break
			}
		}
		hop.Timeout = allTimeout

		result.Hops = append(result.Hops, &hop)

		// Check if we reached the destination
		if hopIP == targetIP {
			log.Info("Reached destination", svc1log.SafeParam("hop", ttl), svc1log.SafeParam("targetIP", targetIP))
			result.Completed = true
			break
		}

		// Log progress every 5 hops
		if ttl%5 == 0 {
			log.Info("Traceroute progress", svc1log.SafeParam("currentHop", ttl), svc1log.SafeParam("maxHops", maxHops))
		}
	}

	return result, nil
}

// newICMPTracer creates a new ICMP-based traceroute implementation.
// Requires elevated privileges for raw socket access.
func newICMPTracer(destIP net.IP) (*icmpTracer, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("failed to create ICMP socket (may require root privileges): %w", err)
	}

	return &icmpTracer{
		conn:   conn,
		destIP: destIP,
		id:     syscall.Getpid() & 0xffff,
	}, nil
}

// SendProbe sends an ICMP Echo Request with the specified TTL and waits for a response.
func (t *icmpTracer) SendProbe(ttl int, timeout time.Duration) (string, error) {
	// Set TTL on socket
	err := t.conn.IPv4PacketConn().SetTTL(ttl)
	if err != nil {
		return "", fmt.Errorf("failed to set TTL: %w", err)
	}

	// Create ICMP Echo Request
	seq := ttl
	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   t.id,
			Seq:  seq,
			Data: []byte("networkscan-traceroute"),
		},
	}

	data, err := msg.Marshal(nil)
	if err != nil {
		return "", fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	// Send probe
	dest := &net.IPAddr{IP: t.destIP}
	_, err = t.conn.WriteTo(data, dest)
	if err != nil {
		return "", fmt.Errorf("failed to send ICMP probe: %w", err)
	}

	// Wait for reply
	reply := make([]byte, 1500)
	_ = t.conn.SetReadDeadline(time.Now().Add(timeout))
	n, peer, err := t.conn.ReadFrom(reply)
	if err != nil {
		return "", fmt.Errorf("timeout waiting for ICMP reply: %w", err)
	}

	// Parse reply - could be Time Exceeded or Echo Reply
	msg, err = icmp.ParseMessage(ipv4.ICMPTypeTimeExceeded.Protocol(), reply[:n])
	if err != nil {
		return "", fmt.Errorf("failed to parse ICMP reply: %w", err)
	}

	// Check if it's the expected message type (Time Exceeded or Echo Reply)
	if msg.Type != ipv4.ICMPTypeTimeExceeded && msg.Type != ipv4.ICMPTypeEchoReply {
		return "", fmt.Errorf("unexpected ICMP message type: %v", msg.Type)
	}

	return peer.(*net.IPAddr).IP.String(), nil
}

// Close releases the ICMP socket resources.
func (t *icmpTracer) Close() error {
	return t.conn.Close()
}

// newUDPTracer creates a new UDP-based traceroute implementation.
// Requires privileges for ICMP socket to receive Time Exceeded messages.
func newUDPTracer(destIP net.IP, port int) (*udpTracer, error) {
	// Create UDP sending socket
	sendConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: destIP, Port: port})
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP socket: %w", err)
	}

	// Create ICMP receiving socket for time exceeded messages
	recvConn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		_ = sendConn.Close()
		return nil, fmt.Errorf("failed to create ICMP socket (may require root privileges): %w", err)
	}

	return &udpTracer{
		sendConn: sendConn,
		recvConn: recvConn,
		destIP:   destIP,
		port:     port,
	}, nil
}

// SendProbe sends a UDP packet with the specified TTL and waits for ICMP response.
func (t *udpTracer) SendProbe(ttl int, timeout time.Duration) (string, error) {
	// Set TTL on UDP socket using syscall
	rawConn, err := t.sendConn.SyscallConn()
	if err != nil {
		return "", fmt.Errorf("failed to get raw connection: %w", err)
	}

	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	})
	if err != nil || sockErr != nil {
		return "", fmt.Errorf("failed to set TTL: %w", err)
	}

	// Send UDP packet
	_, err = t.sendConn.Write([]byte("networkscan-traceroute"))
	if err != nil {
		return "", fmt.Errorf("failed to send UDP probe: %w", err)
	}

	// Wait for ICMP Time Exceeded or Destination Unreachable reply
	reply := make([]byte, 1500) // 1500 is the standard Ethernet MTU (Maximum Transmission Unit)
	_ = t.recvConn.SetReadDeadline(time.Now().Add(timeout))
	n, peer, err := t.recvConn.ReadFrom(reply)
	if err != nil {
		return "", fmt.Errorf("timeout waiting for ICMP reply: %w", err)
	}

	// Parse ICMP reply - could be Time Exceeded or Destination Unreachable
	msg, err := icmp.ParseMessage(ipv4.ICMPTypeTimeExceeded.Protocol(), reply[:n])
	if err != nil {
		return "", fmt.Errorf("failed to parse ICMP reply: %w", err)
	}

	// Check if it's the expected message type (Time Exceeded or Destination Unreachable)
	if msg.Type != ipv4.ICMPTypeTimeExceeded && msg.Type != ipv4.ICMPTypeDestinationUnreachable {
		return "", fmt.Errorf("unexpected ICMP message type: %v", msg.Type)
	}

	return peer.(*net.IPAddr).IP.String(), nil
}

// Close releases both UDP and ICMP socket resources.
func (t *udpTracer) Close() error {
	if err := t.sendConn.Close(); err != nil {
		return err
	}
	return t.recvConn.Close()
}
