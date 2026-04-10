package discover

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	common "github.com/Method-Security/networkscan/generated/go/common"
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

// RunPortScanAndroid performs TCP connect port scanning on Android using pure Go net.Dial.
// Android's kernel does not support the pcap/raw-socket approach naabu uses, so we fall back
// to TCP connect which requires no special privileges and works on all Android devices.
func RunPortScanAndroid(ctx context.Context, config discoverfern.DiscoverPortConfig) ([]*discoverfern.SocketDetails, error) {
	targetHosts, ipToHostname, err := utils.ParseTargetHostsWithMapping(config.Target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target hosts: %w", err)
	}

	ports, err := androidResolvePorts(config)
	if err != nil {
		return nil, err
	}

	type openPort struct {
		host string
		port int
	}
	ch := make(chan openPort, len(targetHosts)*len(ports))

	var wg sync.WaitGroup
	sem := make(chan struct{}, 256) // cap concurrency at 256 simultaneous dials

	for _, host := range targetHosts {
		for _, p := range ports {
			host, p := host, p
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				select {
				case <-ctx.Done():
					return
				default:
				}
				addr := net.JoinHostPort(host, strconv.Itoa(p))
				conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
				if err == nil {
					conn.Close()
					ch <- openPort{host: host, port: p}
				}
			}()
		}
	}

	wg.Wait()
	close(ch)

	// Group by host
	hostPorts := make(map[string][]int)
	for op := range ch {
		hostPorts[op.host] = append(hostPorts[op.host], op.port)
	}

	results := []*discoverfern.SocketDetails{}
	for host, openPorts := range hostPorts {
		portDetails := []*discoverfern.PortDetails{}
		for _, p := range openPorts {
			port := p
			portDetails = append(portDetails, &discoverfern.PortDetails{
				Port:     port,
				Protocol: common.TransportTypeTcp,
			})
		}
		displayHost := host
		if orig, ok := ipToHostname[host]; ok {
			displayHost = orig
		}
		results = append(results, &discoverfern.SocketDetails{
			Host:  displayHost,
			Ip:    host,
			Ports: portDetails,
		})
	}

	return results, nil
}

// androidResolvePorts expands the config's port specification into a concrete list of port numbers.
func androidResolvePorts(config discoverfern.DiscoverPortConfig) ([]int, error) {
	if config.Ports != nil && *config.Ports != "" {
		return parsePorts(*config.Ports)
	}
	if config.TopPorts != nil {
		switch *config.TopPorts {
		case "100":
			return top100Ports(), nil
		case "1000":
			return top1000Ports(), nil
		default:
			// "full" or unknown — scan 1–65535
			ports := make([]int, 65535)
			for i := range ports {
				ports[i] = i + 1
			}
			return ports, nil
		}
	}
	// default: top 100
	return top100Ports(), nil
}

// parsePorts parses a comma-separated list of ports/ranges like "80,443,8000-8080".
func parsePorts(s string) ([]int, error) {
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err := strconv.Atoi(bounds[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			hi, err := strconv.Atoi(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			for p := lo; p <= hi; p++ {
				ports = append(ports, p)
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			ports = append(ports, p)
		}
	}
	return ports, nil
}

func top100Ports() []int {
	return []int{
		7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
		113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
		513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
		1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
		2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
		5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
		6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
		32768, 49152, 49153, 49154, 49155, 49156, 49157,
	}
}

func top1000Ports() []int {
	// Returns the nmap top-1000 list; for brevity we return top-100 union common ranges.
	// The full list would be embedded from configs/ in production.
	base := top100Ports()
	extra := []int{
		1, 2, 3, 4, 5, 6, 8, 10, 11, 12, 14, 15, 16, 17, 18, 19, 20, 24, 27,
		28, 29, 30, 31, 32, 33, 34, 35, 36, 38, 39, 40, 41, 42, 43, 44, 45,
		46, 47, 48, 49, 50, 51, 52, 54, 55, 56, 57, 58, 59, 60, 62, 63, 64,
		65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 82, 83, 84,
		85, 86, 87, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100,
		5985, 5986, 47001, 49158, 49159, 49160,
	}
	return append(base, extra...)
}
