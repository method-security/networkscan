package discover

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/utils"
)

// isAndroid returns true when running on an Android kernel.
func isAndroid() bool {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(data)), "android")
}

// RunHostDiscoveryAndroid discovers live hosts on Android using ICMP ping via the system ping binary.
// Android's kernel does not support the pcap/raw-socket approach naabu uses, so we fall back to
// /system/bin/ping which is available on all Android devices.
func RunHostDiscoveryAndroid(ctx context.Context, target string) ([]*discoverfern.HostDetails, error) {
	targetHosts, err := utils.ParseTargetHosts(target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target hosts: %w", err)
	}

	results := []*discoverfern.HostDetails{}
	type pingResult struct {
		host string
		ip   string
		live bool
	}
	ch := make(chan pingResult, len(targetHosts))

	// Run pings concurrently — Android ping is slow (1 packet, 1s timeout each).
	sem := make(chan struct{}, 64) // cap concurrency
	for _, h := range targetHosts {
		h := h
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			select {
			case <-ctx.Done():
				ch <- pingResult{host: h, live: false}
				return
			default:
			}
			live := androidPing(h)
			ip := h
			hostname := ""
			if net.ParseIP(h) == nil {
				// h is a hostname — resolve it
				addrs, err := net.LookupHost(h)
				if err == nil && len(addrs) > 0 {
					ip = addrs[0]
					hostname = h
				}
			} else {
				// Attempt reverse lookup
				names, err := net.LookupAddr(h)
				if err == nil && len(names) > 0 {
					hostname = strings.TrimSuffix(names[0], ".")
				}
			}
			_ = hostname
			ch <- pingResult{host: hostname, ip: ip, live: live}
		}()
	}

	for range targetHosts {
		r := <-ch
		if r.live {
			results = append(results, &discoverfern.HostDetails{
				Host: r.host,
				Ip:   r.ip,
			})
		}
	}

	return results, nil
}

// androidPing sends a single ICMP echo request using the system ping binary and returns true if the host responds.
func androidPing(host string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// -c 1 = 1 packet, -W 1 = 1 second wait
	cmd := exec.CommandContext(ctx, "/system/bin/ping", "-c", "1", "-W", "1", host)
	return cmd.Run() == nil
}
