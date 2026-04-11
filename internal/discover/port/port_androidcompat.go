//go:build androidcompat

package discover

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	common "github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/Method-Security/networkscan/utils"
)

// RunPortScan is the androidcompat build's entry point for port scanning.
// It uses pure-Go TCP connect scans (no raw sockets / pcap required).
func RunPortScan(ctx context.Context, config discoverfern.DiscoverPortConfig) (*discoverfern.DiscoverPortReport, error) {
	log := svc1log.FromContext(ctx)
	errors := []string{}

	log.Info("Running port scan (Android)", svc1log.SafeParam("validate", config.Validate))

	if config.Validate {
		config = ensureRequiredPorts(config, requiredPorts)
	}

	portscanResult, err := RunPortScanAndroid(ctx, config)
	if err != nil {
		errors = append(errors, err.Error())
	}

	if config.Validate {
		shouldValidate := false

		if config.MaxOpenPortsValidationThreshold != nil && *config.MaxOpenPortsValidationThreshold > 0 {
			openPortCount := countOpenPorts(portscanResult)
			if openPortCount > *config.MaxOpenPortsValidationThreshold {
				log.Warn("Number of open ports exceeds validation threshold, triggering validation",
					svc1log.SafeParam("openPorts", openPortCount),
					svc1log.SafeParam("threshold", *config.MaxOpenPortsValidationThreshold))
				errors = append(errors, fmt.Sprintf("validation triggered due to count of open ports exceeding threshold (%d > %d)", openPortCount, *config.MaxOpenPortsValidationThreshold)) // Note: DD Metrics is generated off of this error line. Please update with caution
				shouldValidate = true
			}
		}
		hasOpen := hasOpenRequiredPorts(portscanResult, requiredPorts)
		if hasOpen {
			log.Warn("Required validation ports are open, triggering validation", svc1log.SafeParam("requiredPorts", requiredPorts))
			errors = append(errors, fmt.Sprintf("validation triggered due to one or more validation ports being open: %v", requiredPorts)) // Note: DD Metrics is generated off of this error line. Please update with caution
			shouldValidate = true
		}

		if !shouldValidate {
			log.Info("Skipping validation, conditions not met")
			return &discoverfern.DiscoverPortReport{
				Config: &config, Result: &discoverfern.DiscoverPortResult{Sockets: portscanResult}, Errors: errors}, nil
		}

		validatedPorts, validationErrors := validatePortScan(ctx, config, portscanResult)
		portscanResult = validatedPorts
		errors = append(errors, validationErrors...)
	}

	return &discoverfern.DiscoverPortReport{
		Config: &config, Result: &discoverfern.DiscoverPortResult{Sockets: portscanResult}, Errors: errors}, nil
}

// RunPortScanAndroid performs TCP connect port scanning on Android using pure Go net.Dial.
// Android kernels do not support the pcap/raw-socket approach naabu uses, so we fall back
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

	var mu sync.Mutex
	var found []openPort

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
				conn, dialErr := net.DialTimeout("tcp", addr, 1*time.Second)
				if dialErr == nil {
					_ = conn.Close()
					mu.Lock()
					found = append(found, openPort{host: host, port: p})
					mu.Unlock()
				}
			}()
		}
	}

	wg.Wait()

	// Group by host
	hostPorts := make(map[string][]int)
	for _, op := range found {
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
// When both TopPorts and Ports are set (e.g. validate mode appends required ports on top of a top-N
// scan via ensureRequiredPorts), both are expanded and merged so neither list is silently dropped.
func androidResolvePorts(config discoverfern.DiscoverPortConfig) ([]int, error) {
	var all []int

	if config.TopPorts != nil {
		expanded, err := expandTopPorts(*config.TopPorts)
		if err != nil {
			return nil, err
		}
		all = append(all, expanded...)
	}

	if config.Ports != nil && *config.Ports != "" {
		explicit, err := parsePorts(*config.Ports)
		if err != nil {
			return nil, err
		}
		all = append(all, explicit...)
	}

	if len(all) > 0 {
		return dedupPorts(all), nil
	}

	// default: top 100
	return top100Ports(), nil
}

// expandTopPorts converts a top-ports string ("100", "1000", "full") into a port list.
func expandTopPorts(topPorts string) ([]int, error) {
	switch topPorts {
	case "100":
		return top100Ports(), nil
	case "1000":
		return top1000Ports(), nil
	default:
		// "full" or any unknown value — scan the full range
		ports := make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
		return ports, nil
	}
}

// dedupPorts returns a deduplicated copy of the input slice, preserving order.
func dedupPorts(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
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

// top1000Ports returns the nmap top-1000 port list.
// The port spec string is sourced from naabu's runner.NmapTop1000 constant — same data,
// no vendor patch required.
func top1000Ports() []int {
	const nmapTop1000 = "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100," +
		"106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280," +
		"301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524," +
		"541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705," +
		"711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981," +
		"987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119," +
		"1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169," +
		"1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248," +
		"1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443," +
		"1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666," +
		"1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875," +
		"1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038," +
		"2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144," +
		"2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383," +
		"2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702," +
		"2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003," +
		"3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269," +
		"3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527," +
		"3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869," +
		"3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111," +
		"4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998," +
		"5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214," +
		"5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555," +
		"5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859," +
		"5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989," +
		"5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547," +
		"6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969," +
		"7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625," +
		"7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031," +
		"8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333," +
		"8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003," +
		"9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415," +
		"9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929," +
		"9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566," +
		"10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456," +
		"13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012," +
		"16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350," +
		"19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800," +
		"25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337," +
		"32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443," +
		"44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300," +
		"50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555," +
		"55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000," +
		"65129,65389"
	ports, _ := parsePorts(nmapTop1000)
	return ports
}
