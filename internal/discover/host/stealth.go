package discover

import (
	// Standard
	"context"
	"net"
	"time"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	// Internal
	"github.com/Method-Security/networkscan/utils"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// performReverseLookupSweep performs reverse DNS lookups on all IPs in a CIDR range
// Returns a list of IPs that have reverse DNS entries (potential active hosts)
func performReverseLookupSweep(target string) ([]string, error) {
	// Get all possible IPs from the target
	allHosts, err := utils.ParseTargetHosts(target)
	if err != nil {
		return nil, err
	}

	var hostsWithReverseDNS []string

	// Perform reverse lookup on each IP
	for _, host := range allHosts {
		ip := net.ParseIP(host)
		if ip == nil {
			// If it's not an IP, assume it's a hostname and include it
			hostsWithReverseDNS = append(hostsWithReverseDNS, host)
			continue
		}

		// Perform reverse lookup
		names, err := net.LookupAddr(host)
		if err == nil && len(names) > 0 {
			// Found reverse DNS entry, likely an active host
			hostsWithReverseDNS = append(hostsWithReverseDNS, host)
		}
	}

	return hostsWithReverseDNS, nil
}

// getStealthHostDiscovery performs stealth host discovery using ICMP ping
// Requires root privileges for raw socket access
func getStealthHostDiscovery(ctx context.Context, config discoverfern.DiscoverHostConfig) ([]*discoverfern.HostDetails, error) {
	log := svc1log.FromContext(ctx)

	// Get stealth delay configuration (but don't calculate delay yet - do it per attempt)
	var sleepPtr, jitterPtr *int
	if config.Stealth != nil {
		sleepPtr = config.Stealth.Sleep
		jitterPtr = config.Stealth.Jitter
	}

	// Determine target hosts based on reverse lookup setting
	var targetHosts []string
	var err error

	if config.Stealth.ReverseLookup != nil && *config.Stealth.ReverseLookup {
		// Perform reverse lookup sweep first
		log.Debug("Performing reverse DNS lookup sweep", svc1log.SafeParam("target", config.Target))
		targetHosts, err = performReverseLookupSweep(config.Target)
		if err != nil {
			return nil, err
		}

		// If no hosts found with reverse DNS, fall back to full range scan
		if len(targetHosts) == 0 {
			log.Debug("No reverse DNS entries found, falling back to full range scan")
			targetHosts, err = utils.ParseTargetHosts(config.Target)
			if err != nil {
				return nil, err
			}
		} else {
			log.Debug("Found hosts with reverse DNS entries", svc1log.SafeParam("count", len(targetHosts)))
		}
	} else {
		// Parse target hosts using the utility function
		targetHosts, err = utils.ParseTargetHosts(config.Target)
		if err != nil {
			return nil, err
		}
	}

	// Calculate initial delay for logging purposes
	initialDelay := utils.CalculateStealthDelay(sleepPtr, jitterPtr)

	log.Debug("Starting stealth host discovery",
		svc1log.SafeParam("target", config.Target),
		svc1log.SafeParam("hosts", len(targetHosts)),
		svc1log.SafeParam("base_delay_ms", initialDelay.Milliseconds()))

	var liveHosts []*discoverfern.HostDetails

	// Scan each host with jittered delay
	for i, host := range targetHosts {
		if i > 0 {
			// Calculate a new jittered delay for each attempt
			delay := utils.CalculateStealthDelay(sleepPtr, jitterPtr)

			log.Info("Applying stealth delay before scanning host",
				svc1log.SafeParam("host", host),
				svc1log.SafeParam("delay_ms", delay.Milliseconds()))

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		// Progress logging every 50 hosts for stealth
		if i%50 == 0 && i > 0 {
			log.Debug("Stealth scan progress",
				svc1log.SafeParam("completed", i),
				svc1log.SafeParam("total", len(targetHosts)),
				svc1log.SafeParam("found", len(liveHosts)))
		}

		hostDetail := checkHostAlive(ctx, host)
		if hostDetail != nil {
			liveHosts = append(liveHosts, hostDetail)
			log.Debug("Found live host", svc1log.SafeParam("host", hostDetail.Ip))
		}
	}

	return liveHosts, nil
}

// checkHostAlive performs ICMP ping to determine if a host is alive
func checkHostAlive(ctx context.Context, host string) *discoverfern.HostDetails {
	if pingHost(ctx, host) {
		return &discoverfern.HostDetails{
			Ip:   host,
			Host: host,
		}
	}
	return nil
}

// pingHost performs ICMP ping to check if a host is reachable
func pingHost(ctx context.Context, host string) bool {
	// Parse the target IP
	targetIP := net.ParseIP(host)
	if targetIP == nil {
		// Try to resolve hostname to IP
		addrs, err := net.LookupIP(host)
		if err != nil || len(addrs) == 0 {
			return false
		}
		targetIP = addrs[0]
	}

	// Detect IP version and select appropriate ICMP parameters
	var network, listenAddr string
	var icmpType icmp.Type
	var replyType icmp.Type
	var proto int

	if utils.IsIPv6(targetIP.String()) {
		network = "ip6:ipv6-icmp"
		listenAddr = "::"
		icmpType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
		proto = 58 // ICMPv6 protocol number
	} else {
		network = "ip4:icmp"
		listenAddr = "0.0.0.0"
		icmpType = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply
		proto = 1 // ICMPv4 protocol number
	}

	// Create ICMP connection
	conn, err := icmp.ListenPacket(network, listenAddr)
	if err != nil {
		return false
	}
	defer func() {
		_ = conn.Close()
	}()

	// Create ICMP message
	msg := &icmp.Message{
		Type: icmpType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte("ping"),
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	// Set timeout
	deadline := time.Now().Add(2 * time.Second)
	err = conn.SetDeadline(deadline)
	if err != nil {
		return false
	}

	// Send ping
	_, err = conn.WriteTo(msgBytes, &net.IPAddr{IP: targetIP})
	if err != nil {
		return false
	}

	// Read response
	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		return false
	}

	// Parse reply
	replyMsg, err := icmp.ParseMessage(proto, reply[:n])
	if err != nil {
		return false
	}

	// Check if it's an echo reply and verify it's our ping
	if replyMsg.Type == replyType {
		if echoReply, ok := replyMsg.Body.(*icmp.Echo); ok {
			return echoReply.ID == 1
		}
	}
	return false
}
