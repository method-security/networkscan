# Discover

The `networkscan discover` command performs network discovery tasks to identify live hosts, open ports, running services, TLS configurations, and network routes.

## Usage

```bash
networkscan discover [command]
```

## Available Commands

- **host scan**: Identify live hosts within a given IP, hostname, or CIDR range
- **host arp**: Read the host's ARP table to inspect IP-to-MAC address mappings
- **port**: Scan target hosts for open TCP ports
- **service**: Identify and fingerprint network services on a target host
- **tls**: Retrieve and analyze TLS configuration and certificate details
- **route**: Perform traceroute to trace the network path to a target
- **domain**: Discover domain information from a target host

## Commands

### Host

Host-level discovery and inspection commands.

#### Scan

Identify live hosts within a given IP, hostname, or CIDR range using various discovery techniques.

##### Usage
```bash
networkscan discover host scan --target 192.168.1.0/24 --scan-type ICMP_ECHO
```

##### Stealth Mode
Use stealth mode for slower, less detectable scans:
```bash
networkscan discover host scan --target 192.168.1.0/24 --sleep 2 --jitter 10 --reverse-lookup
```

##### Help Text
```bash
networkscan discover host scan -h
Identify live hosts within a given IP, hostname, or CIDR range using various discovery techniques.

Usage:
  networkscan discover host scan [flags]

Flags:
  -h, --help                  help for scan
      --jitter int            Jitter percentage (0-100) to randomize sleep delay for stealth scan
      --reverse-lookup        Perform reverse DNS lookup sweep first to identify potential targets
      --scan-type string      Discovery scan type: TCP_SYN, ICMP_ECHO, ICMP_TIMESTAMP, ARP, or ICMP_ADDRESS_MASK (not needed for stealth mode) (default "ICMP_ECHO")
      --sleep int             Sleep delay in seconds between hosts for stealth scan (stealth mode enabled when sleep > 0)
      --target string         Target IP address, hostname, or CIDR range to scan for live hosts

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

#### ARP

Read the host's ARP table to inspect IP-to-MAC address mappings and associated network interface information.

##### Usage
```bash
networkscan discover host arp
```

##### Help Text
```bash
networkscan discover host arp -h
Read the host's ARP table to inspect IP-to-MAC address mappings and associated network interface information.

Usage:
  networkscan discover host arp [flags]

Flags:
  -h, --help   help for arp

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```


### Port

Scan target hosts for open TCP ports using customizable scan types and port ranges. Supports single IPs, hostnames, CIDR ranges, and IP ranges.

#### Usage
```bash
networkscan discover port --target 127.0.0.1 --ports 22,80,443
networkscan discover port --target 192.168.1.0/24 --top-ports 100
```

#### Port Validation
Service validation is enabled by default. Disable it explicitly when needed:
```bash
networkscan discover port --target example.com --top-ports 100 --validate=false
```

#### Stealth Mode
Use stealth mode for slower, less detectable scans:
```bash
networkscan discover port --target 192.168.1.1 --ports 1-1000 --sleep 1 --jitter 20
```

#### Help Text
```bash
networkscan discover port -h
Scan target hosts for open TCP ports using customizable scan types and port ranges. Supports single IPs, hostnames, CIDR ranges, and IP ranges.

Usage:
  networkscan discover port [flags]

Flags:
  -h, --help                            help for port
      --jitter int                      Jitter percentage (0-100) to randomize sleep delay for stealth scan
      --packets-per-second int          Packets per second to send (default 250)
      --ports string                    Comma-separated list or range of TCP ports to scan (e.g., 22,80,443 or 1-1024)
      --scan-type string                Port scan type: SYN or CONNECT (default "SYN")
      --sleep int                       Sleep delay in seconds between port scans for stealth scan (stealth mode enabled when sleep > 0)
      --target string                   Target IP address, FQDN, CIDR range, or IP range to scan for open ports
      --threads int                     Number of concurrent threads to use during port scanning (default 200)
      --top-ports string                Scan the top N most common TCP ports (options: full, 100, 1000)
      --validate                        Validate open ports by using service detection techniques (default true)
      --validate-attempt-timeout int               Timeout in seconds for each service detection attempt (default 10)
      --validate-threads int                       Number of concurrent threads to use during service detection (default 200)
      --max-open-ports-validation-threshold int    Trigger validation warning when more than this many ports are open (default 50)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Service

Identify and fingerprint network services on a target host or specific port.

#### TCP Service Discovery
```bash
networkscan discover service --target 127.0.0.1:443
networkscan discover service --target example.com:22
```

#### UDP Service Discovery
Use UDP mode to discover common UDP services:
```bash
networkscan discover service --target 192.168.1.1 --udp
```

#### Stealth Mode
Use stealth mode for specific service fingerprinting:
```bash
networkscan discover service --target 192.168.1.1:22 --service-type SSH
```

#### Help Text
```bash
networkscan discover service -h
Identify and fingerprint network services on a target host or specific port. Use --udp to scan common UDP ports.

Usage:
  networkscan discover service [flags]

Flags:
  -h, --help                 help for service
      --fingerprintx-timeout int   Timeout in seconds for fingerprintx attempt (default 20)
      --service-type string        Service type to fingerprint for stealth mode: SSH, HTTP, GRPC, KERBEROS, LDAP, SMB (stealth mode enabled when specified)
      --target string              Target address (IP:port or hostname:port for TCP, IP or hostname for UDP mode)
      --timeout int                Timeout in seconds for each service fingerprinting attempt (default 20)
      --udp                        Enable UDP service discovery mode (scans common UDP ports like DNS, NTP, SNMP, etc.)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### TLS

Retrieve and analyze the TLS configuration and certificate details for one or more target addresses.

#### Usage
```bash
networkscan discover tls --targets 127.0.0.1:443,example.com:443
```

#### Help Text
```bash
networkscan discover tls -h
Retrieve and analyze the TLS configuration and certificate details for one or more target addresses.

Usage:
  networkscan discover tls [flags]

Flags:
  -h, --help               help for tls
      --targets strings    List of target addresses (IP:port or hostname:port) to analyze TLS configuration
      --timeout int        Timeout in seconds for each TLS handshake attempt (default 30)


Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Route

Perform traceroute to trace the network path to one or more target destinations using various probe types (UDP, ICMP).

#### Usage
```bash
networkscan discover route --targets 8.8.8.8
networkscan discover route --targets 192.168.1.1,10.0.0.1 --probe-type UDP --max-hops 20
```

#### Help Text
```bash
networkscan discover route -h
Perform traceroute to trace the network path to a target destination using various probe types (UDP, ICMP, TCP SYN).

Usage:
  networkscan discover route [flags]

Flags:
      --exclude-timeout-hops   Exclude hops that timed out from the results
  -h, --help                   help for route
      --host-ip string         Host IP address for network interface binding
      --max-hops int           Maximum number of hops to trace (default 30)
      --port int               Port number for UDP probes (default: 33434 for UDP)
      --probe-delay int        Delay in milliseconds between probes (default 100)
      --probe-type string      Probe packet type: UDP or ICMP (default "ICMP")
      --probes-per-hop int     Number of probes to send per hop (default 3)
      --targets strings        Target IP addresses or hostnames to trace route to (comma-separated)
      --timeout int            Timeout in seconds for each probe (default 5)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Domain

Discover domain information from a target host using LDAP/SMB discovery and DNS enumeration of domain controllers.

#### Usage
```bash
networkscan discover domain --target 192.168.1.1
networkscan discover domain --target dc.example.com
```

#### Help Text
```bash
networkscan discover domain -h
Discover domain information from a target host using LDAP/SMB discovery and DNS enumeration of domain controllers.

Usage:
  networkscan discover domain [flags]

Flags:
  -h, --help            help for domain
      --target string   Target IP address or hostname to discover domain information from

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
