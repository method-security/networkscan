# Discover

The `networkscan discover` command performs network discovery tasks to identify live hosts, open ports, running services, TLS configurations, and network routes.

## Usage

```bash
networkscan discover [command]
```

## Available Commands

- **host**: Identify live hosts within a given IP, hostname, or CIDR range
- **port**: Scan target hosts for open TCP ports
- **service**: Identify and fingerprint network services on a target host
- **tls**: Retrieve and analyze TLS configuration and certificate details
- **route**: Perform traceroute to trace the network path to a target
- **domain**: Discover domain information from a target host
- **socket**: Connect to a socket and inspect its response

## Commands

### Host

Identify live hosts within a given IP, hostname, or CIDR range using various discovery techniques.

##### Usage
```bash
networkscan discover host --target 192.168.1.0/24 --scan-type ICMP_ECHO
```

##### Stealth Mode
Use stealth mode for slower, less detectable scans:
```bash
networkscan discover host --target 192.168.1.0/24 --sleep 2 --jitter 10 --reverse-lookup
```

##### Help Text
```bash
networkscan discover host -h
Identify live hosts within a given IP, hostname, or CIDR range using various discovery techniques.

Usage:
  networkscan discover host [flags]

Flags:
  -h, --help               help for host
      --jitter int         Jitter percentage (0 to 100) to randomize sleep delay for stealth scan
      --reverse-lookup     Perform reverse DNS lookup sweep first to identify potential targets
      --scan-type string   Discovery scan type: TCP_SYN, ICMP_ECHO, ICMP_TIMESTAMP, ARP, or ICMP_ADDRESS_MASK (not needed for stealth mode) (default "ICMP_ECHO")
      --sleep int          Sleep delay in seconds between hosts for stealth scan (stealth mode enabled when sleep > 0)
      --target string      Target IP address, hostname, or CIDR range to scan for live hosts

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --socks-proxy string   SOCKS5 proxy URL for TCP connections (e.g., socks5://127.0.0.1:1080)
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
Validate discovered ports with service detection:
```bash
networkscan discover port --target example.com --top-ports 100 --validate
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
  -h, --help                                      help for port
      --jitter int                                Jitter percentage (0-100) to randomize sleep delay for stealth scan
      --max-open-ports-validation-threshold int   Trigger validation warning when more than this many ports are open (default: 50) (default 50)
      --packets-per-second int                    Packets per second to send (default: 1000) (default 1000)
      --ports string                              Comma-separated list or range of TCP ports to scan (e.g., 22,80,443 or 1-1024)
      --scan-type string                          Port scan type: SYN (default, requires root) or CONNECT (default "SYN")
      --sleep int                                 Sleep delay in seconds between port scans for stealth scan (stealth mode enabled when sleep > 0)
      --target string                             Target IP address, FQDN, CIDR range, or IP range to scan for open ports
      --threads int                               Number of concurrent threads to use during port scanning (default 25)
      --top-ports string                          Scan the top N most common TCP ports (options: full, 100, 1000)
      --validate                                  Validate open ports by using service detection techniques
      --validate-attempt-timeout int              Timeout in seconds for each service detection attempt (default 30)
      --validate-plugin-threads int               Maximum number of custom service plugins to run concurrently per port during validation (default 10)
      --validate-threads int                      Number of concurrent threads to use during service detection

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --socks-proxy string   SOCKS5 proxy URL for TCP connections (e.g., socks5://127.0.0.1:1080)
  -v, --verbose              Verbose output
```

### Service

Identify and fingerprint network services over TCP or UDP.

#### TCP Service Discovery
```bash
networkscan discover service tcp --targets 127.0.0.1:443
networkscan discover service tcp --targets example.com:22,10.0.0.0/28:443
networkscan discover service tcp --targets '[::1]:443' --threads 10 --plugin-threads 10 --timeout 30
```

#### UDP Service Discovery
```bash
networkscan discover service udp --targets 192.168.1.1,10.0.0.0/28
```

TCP accepts comma-separated sockets, including hostnames, CIDRs, and IP ranges with a port. Use brackets around IPv6 addresses when specifying a port. UDP accepts comma-separated hosts, CIDRs, and IP ranges without a port and probes the registered plugins' default UDP ports. CIDRs include every address, including IPv4 network and broadcast addresses. Hostname targets retain their name for probes that use SNI or a Host header.

#### Concurrency and Timeouts

Both commands share these flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--targets` | Required | Comma-separated TCP sockets or UDP hosts; may also be repeated |
| `--threads` | `10` | Maximum target entries processed concurrently after expansion |
| `--plugin-threads` | `10` | Maximum plugin attempts running concurrently per target |
| `--timeout` | `30` | Timeout in seconds for each plugin attempt |

The timeout starts when a plugin attempt runs, not while it waits for a worker. It is not a deadline for an entire target or scan. A target can take multiple timeout intervals when plugins run in batches; TCP may also try fallback plugins when its default-port probes find no service. Increasing both thread settings increases concurrent work, so choose them together based on container resources and target volume.

For MySQL, the result's `tls` field reports the server greeting's advertised TLS capability, not whether the greeting was encrypted. When that capability cannot be determined, the field is omitted.

#### Stealth Mode
Use stealth mode for specific service fingerprinting:
```bash
networkscan discover service tcp --targets 192.168.1.1:22 --service-type SSH
```

#### Help Text
```bash
networkscan discover service -h
Identify and fingerprint network services over TCP or UDP.

Usage:
  networkscan discover service [command]

Available Commands:
  tcp         Identify and fingerprint TCP services on a target host and port.
  udp         Identify common UDP services on one or more target hosts.

Flags:
  -h, --help   help for service

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --socks-proxy string   SOCKS5 proxy URL for TCP connections (e.g., socks5://127.0.0.1:1080)
  -v, --verbose              Verbose output

Use "networkscan discover service [command] --help" for more information about a command.
```

#### TCP Flags

```bash
networkscan discover service tcp -h
Identify and fingerprint TCP services on a target host and port.

Usage:
  networkscan discover service tcp [flags]

Flags:
  -h, --help                  help for tcp
      --plugin-threads int    Maximum custom service plugins to run concurrently per target (default 10)
      --service-type string   Service type to fingerprint for stealth mode: SSH, HTTP, GRPC, KERBEROS, LDAP, SMB (stealth mode enabled when specified)
      --targets strings       Target addresses (IP:port or hostname:port)
      --threads int           Maximum concurrent target IPs (default 10)
      --timeout int           Timeout in seconds for each service fingerprinting attempt (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --socks-proxy string   SOCKS5 proxy URL for TCP connections (e.g., socks5://127.0.0.1:1080)
  -v, --verbose              Verbose output
```

#### UDP Flags

```bash
networkscan discover service udp -h
Identify common UDP services on one or more target hosts.

Usage:
  networkscan discover service udp [flags]

Flags:
  -h, --help                 help for udp
      --plugin-threads int   Maximum custom service plugins to run concurrently per target (default 10)
      --targets strings      Target IP addresses, hostnames, CIDR ranges, or IP ranges
      --threads int          Maximum concurrent target IPs (default 10)
      --timeout int          Timeout in seconds for each service fingerprinting attempt (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --socks-proxy string   SOCKS5 proxy URL for TCP connections (e.g., socks5://127.0.0.1:1080)
  -v, --verbose              Verbose output
```

### Socket

Connect to a socket and inspect its response. See the command help for transport and payload options.

```bash
networkscan discover socket -h
Open a raw TCP or UDP connection to a target host:port, optionally send a payload, and return the raw response bytes. Useful for banner grabbing, vulnerability probing, and interacting with custom binary protocols.

Usage:
  networkscan discover socket [flags]

Flags:
  -h, --help                     help for socket
      --max-response-bytes int   Maximum response bytes to read (default 10240)
      --protocol string          Transport protocol (tcp or udp) (default "tcp")
      --read-timeout int         Timeout in seconds for connection and read (default 5)
      --send-data string         Data to send (plaintext or \x-escaped hex bytes)
      --target string            Target address (IP:port)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --socks-proxy string   SOCKS5 proxy URL for TCP connections (e.g., socks5://127.0.0.1:1080)
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
  -h, --help              help for tls
      --ja4s              Compute JA4S server-side TLS fingerprint
      --ja4x              Compute JA4X X.509 certificate fingerprint for each certificate
      --jarm              Compute JARM 10-probe TLS fingerprint
      --targets strings   List of target addresses (IP:port or hostname:port) to analyze TLS configuration
      --timeout int       Timeout in seconds for each TLS handshake attempt (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --socks-proxy string   SOCKS5 proxy URL for TCP connections (e.g., socks5://127.0.0.1:1080)
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
      --jitter int             Jitter percentage (0-100) to randomize sleep
      --max-hops int           Maximum number of hops to trace (default: 30) (default 30)
      --port int               Port number for UDP probes (default: 33434 for UDP)
      --probe-delay int        Delay in milliseconds between probes (default: 100) (default 100)
      --probe-type string      Probe packet type: UDP or ICMP (default: ICMP) (default "ICMP")
      --probes-per-hop int     Number of probes to send per hop (default: 3) (default 3)
      --sleep int              Sleep duration in seconds between targets
      --targets strings        Target IP addresses or hostnames to trace route to (comma-separated)
      --timeout int            Timeout in seconds for each probe (default: 5) (default 5)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --socks-proxy string   SOCKS5 proxy URL for TCP connections (e.g., socks5://127.0.0.1:1080)
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
      --socks-proxy string   SOCKS5 proxy URL for TCP connections (e.g., socks5://127.0.0.1:1080)
  -v, --verbose              Verbose output
```
