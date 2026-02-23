// Package route implements traceroute functionality for discovering network paths to targets.
package route

import (
	// Standard
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	// Internal
	"github.com/Method-Security/networkscan/internal/discover/route/udpsocket"
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

	log.Info("Starting traceroute", svc1log.SafeParam("targets", config.Targets), svc1log.SafeParam("maxHops", config.MaxHops), svc1log.SafeParam("probeType", config.ProbeType))

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
		tracerouteResult, err := performTraceroute(ctx, target, targetIP, config)
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

	// Fall back to first IP
	return ips[0].String(), nil
}

// performTraceroute executes the actual traceroute operation using the specified probe type.
// It sends probes with incrementing TTL values and collects responses from intermediate hops.
func performTraceroute(ctx context.Context, target, targetIP string, config discoverfern.DiscoverRouteConfig) (*discoverfern.TracerouteResult, error) {
	log := svc1log.FromContext(ctx)

	result := &discoverfern.TracerouteResult{
		Target:    target,
		TargetIp:  targetIP,
		Hops:      []*discoverfern.TracerouteHop{},
		Completed: false,
	}

	destIP := net.ParseIP(targetIP)
	if destIP == nil {
		return nil, fmt.Errorf("invalid target IP: %s", targetIP)
	}

	var tr tracer
	var err error

	log.Info("Initializing tracer", svc1log.SafeParam("probeType", config.ProbeType), svc1log.SafeParam("port", config.Port))

	// Create appropriate tracer based on probe type
	switch config.ProbeType {
	case discoverfern.ProbeTypeIcmp:
		tr, err = newICMPTracer(destIP)
	case discoverfern.ProbeTypeUdp:
		tr, err = newUDPTracer(destIP, config.Port)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create tracer: %w", err)
	}
	defer func() { _ = tr.Close() }()

	// Perform traceroute with increasing TTL
	for ttl := 1; ttl <= config.MaxHops; ttl++ {
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
		// Probes must be sequential to avoid socket races on the shared tracer
		rtts := make([]float64, config.ProbesPerHop)
		timeouts := make([]bool, config.ProbesPerHop)
		var hopIP string

		for i := 0; i < config.ProbesPerHop; i++ {
			start := time.Now()
			replyIP, err := tr.SendProbe(ttl, time.Duration(config.Timeout)*time.Second)
			rtt := time.Since(start).Seconds() * 1000 // Convert to milliseconds

			if err != nil {
				timeouts[i] = true
			} else {
				rtts[i] = rtt
				if hopIP == "" {
					hopIP = replyIP
				}
			}

			// Configurable delay between probes
			if i < config.ProbesPerHop-1 {
				time.Sleep(time.Duration(config.ProbeDelay) * time.Millisecond)
			}
		}

		// Set IP address and try hostname resolution
		if hopIP != "" {
			hop.IpAddress = &hopIP
			if hostname, err := net.LookupAddr(hopIP); err == nil && len(hostname) > 0 {
				hop.Hostname = &hostname[0]
			}
		}

		// Collect RTT values for all successful probes
		var validRtts []float64
		for i := 0; i < config.ProbesPerHop; i++ {
			if !timeouts[i] {
				validRtts = append(validRtts, rtts[i])
			}
		}
		hop.Rtts = validRtts

		// Check if all probes timed out
		allTimeout := true
		for i := 0; i < config.ProbesPerHop; i++ {
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
			log.Info("Traceroute progress", svc1log.SafeParam("currentHop", ttl), svc1log.SafeParam("maxHops", config.MaxHops))
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

	// Wait for reply with retries to handle out-of-order responses
	reply := make([]byte, 1500)
	deadline := time.Now().Add(timeout)
	_ = t.conn.SetReadDeadline(deadline)

	for time.Now().Before(deadline) {
		n, peer, err := t.conn.ReadFrom(reply)
		if err != nil {
			return "", fmt.Errorf("timeout waiting for ICMP reply: %w", err)
		}

		// Parse reply - could be Time Exceeded or Echo Reply
		msg, err := icmp.ParseMessage(ipv4.ICMPTypeTimeExceeded.Protocol(), reply[:n])
		if err != nil {
			continue // Skip malformed packets
		}

		// Validate the response matches our probe
		switch msg.Type {
		case ipv4.ICMPTypeTimeExceeded:
			// Time Exceeded contains the original packet in its body
			// We need to extract and validate the original Echo Request
			timeExceeded, ok := msg.Body.(*icmp.TimeExceeded)
			if !ok {
				continue
			}

			// Parse the original ICMP message from the TimeExceeded data
			// The data contains: original IP header (variable length 20-60 bytes) + original ICMP message
			if len(timeExceeded.Data) < 1 {
				continue // Not enough data to read IP header
			}

			// Extract IP header length from IHL field (lower 4 bits of first byte)
			// IHL is in 32-bit (4-byte) words, so multiply by 4 to get bytes
			ipHeaderLen := int(timeExceeded.Data[0]&0x0F) * 4
			if ipHeaderLen < 20 || ipHeaderLen > 60 {
				continue // Invalid IP header length
			}

			// Ensure we have enough data for IP header + minimum ICMP header
			if len(timeExceeded.Data) < ipHeaderLen+8 {
				continue // Not enough data
			}

			// Skip the IP header to get to the ICMP message
			origICMP, err := icmp.ParseMessage(ipv4.ICMPTypeEcho.Protocol(), timeExceeded.Data[ipHeaderLen:])
			if err != nil {
				continue
			}

			// Validate it's our Echo Request
			origEcho, ok := origICMP.Body.(*icmp.Echo)
			if !ok {
				continue
			}

			if origEcho.ID != t.id || origEcho.Seq != seq {
				continue // Not our packet, keep waiting
			}

			return peer.(*net.IPAddr).IP.String(), nil

		case ipv4.ICMPTypeEchoReply:
			// Echo Reply - validate ID and Sequence
			echoReply, ok := msg.Body.(*icmp.Echo)
			if !ok {
				continue
			}

			if echoReply.ID != t.id || echoReply.Seq != seq {
				continue // Not our packet, keep waiting
			}

			return peer.(*net.IPAddr).IP.String(), nil

		default:
			continue // Unexpected message type, keep waiting
		}
	}

	return "", fmt.Errorf("timeout: no matching ICMP reply received")
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
	// Set TTL on UDP socket (platform-specific implementation)
	if err := udpsocket.SetUDPSocketTTL(t.sendConn, ttl); err != nil {
		return "", err
	}

	// Get local port for validation
	localAddr := t.sendConn.LocalAddr().(*net.UDPAddr)
	localPort := localAddr.Port

	// Send UDP packet with unique payload
	payload := []byte("networkscan-traceroute")
	_, err := t.sendConn.Write(payload)
	if err != nil {
		return "", fmt.Errorf("failed to send UDP probe: %w", err)
	}

	// Wait for ICMP Time Exceeded or Destination Unreachable reply with retries
	reply := make([]byte, 1500) // 1500 is the standard Ethernet MTU (Maximum Transmission Unit)
	deadline := time.Now().Add(timeout)
	_ = t.recvConn.SetReadDeadline(deadline)

	for time.Now().Before(deadline) {
		n, peer, err := t.recvConn.ReadFrom(reply)
		if err != nil {
			return "", fmt.Errorf("timeout waiting for ICMP reply: %w", err)
		}

		// Parse ICMP reply - could be Time Exceeded or Destination Unreachable
		msg, err := icmp.ParseMessage(ipv4.ICMPTypeTimeExceeded.Protocol(), reply[:n])
		if err != nil {
			continue // Skip malformed packets
		}

		// Validate the response matches our probe
		var icmpData []byte
		switch msg.Type {
		case ipv4.ICMPTypeTimeExceeded:
			timeExceeded, ok := msg.Body.(*icmp.TimeExceeded)
			if !ok {
				continue
			}
			icmpData = timeExceeded.Data

		case ipv4.ICMPTypeDestinationUnreachable:
			destUnreach, ok := msg.Body.(*icmp.DstUnreach)
			if !ok {
				continue
			}
			icmpData = destUnreach.Data

		default:
			continue // Unexpected message type, keep waiting
		}

		// The ICMP data contains: original IP header (variable length 20-60 bytes) + original UDP header (8 bytes) + payload
		if len(icmpData) < 1 {
			continue // Not enough data to read IP header
		}

		// Extract IP header length from IHL field (lower 4 bits of first byte)
		// IHL is in 32-bit (4-byte) words, so multiply by 4 to get bytes
		ipHeaderLen := int(icmpData[0]&0x0F) * 4
		if ipHeaderLen < 20 || ipHeaderLen > 60 {
			continue // Invalid IP header length
		}

		// Ensure we have enough data for IP header + UDP header
		if len(icmpData) < ipHeaderLen+8 {
			continue // Not enough data
		}

		// Extract UDP header from the original packet (skip variable-length IP header)
		udpHeader := icmpData[ipHeaderLen : ipHeaderLen+8]

		// UDP header format: src port (2 bytes) | dst port (2 bytes) | length (2 bytes) | checksum (2 bytes)
		origSrcPort := int(udpHeader[0])<<8 | int(udpHeader[1])
		origDstPort := int(udpHeader[2])<<8 | int(udpHeader[3])

		// Validate this is our UDP packet
		if origSrcPort != localPort || origDstPort != t.port {
			continue // Not our packet, keep waiting
		}

		return peer.(*net.IPAddr).IP.String(), nil
	}

	return "", fmt.Errorf("timeout: no matching ICMP reply received")
}

// Close releases both UDP and ICMP socket resources.
func (t *udpTracer) Close() error {
	if err := t.sendConn.Close(); err != nil {
		return err
	}
	return t.recvConn.Close()
}
