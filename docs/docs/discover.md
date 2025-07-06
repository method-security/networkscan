# Discover

The `networkscan discover` command performs network discovery tasks to identify live hosts, open ports, running services, and TLS configurations.

## Usage

```bash
networkscan discover [command]
```

## Commands

### Host

Identify live hosts within a given IP, hostname, or CIDR range using various discovery techniques.

#### Usage
```bash
networkscan discover host --target 192.168.1.0/24 --scan-type ICMP_ECHO
```

#### Help Text
```bash
networkscan discover host -h
Identify live hosts within a given IP, hostname, or CIDR range using various discovery techniques.

Usage:
  networkscan discover host [flags]

Flags:
  -h, --help                  help for host
      --scan-type string      Discovery scan type: TCP_SYN, TCP_ACK, ICMP_ECHO, ICMP_TIMESTAMP, ARP, or ICMP_ADDRESS_MASK (default "ICMP_ECHO")
      --target string         Target IP address, hostname, or CIDR range to scan for live hosts

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### OS

Detect and fingerprint the operating system running on a specified host (requires nmap and root privileges).

#### Usage
```bash
networkscan discover os --target 127.0.0.1
```

#### Help Text
```bash
networkscan discover os -h
Detect and fingerprint the operating system running on a specified host (requires nmap and root privileges).

Usage:
  networkscan discover os [flags]

Flags:
  -h, --help            help for os
      --target string   Target IP address or fully qualified domain name (FQDN) for OS fingerprinting

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Port

Scan a target host for open TCP ports using customizable scan types and port ranges.

#### Usage
```bash
networkscan discover port --target 127.0.0.1 --ports 22 --ports 80
```

#### Help Text
```bash
networkscan discover port -h
Scan a target host for open TCP ports using customizable scan types and port ranges.

Usage:
  networkscan discover port [flags]

Flags:
  -h, --help                help for port
      --ports string        Comma-separated list or range of TCP ports to scan (e.g., 22,80,443 or 1-1024)
      --scan-type string    Port scan type: SYN (default, requires root) or CONNECT (default "SYN")
      --target string       Target IP address or FQDN to scan for open ports
      --threads int         Number of concurrent threads to use during port scanning (default 25)
      --top-ports string    Scan the top N most common TCP ports (options: full, 100, 1000)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Service

Identify and fingerprint the network service running on a specific open port of a target host.

#### Usage
```bash
networkscan discover service --target 127.0.0.1 --port 443
```

#### Help Text
```bash
networkscan discover service -h
Identify and fingerprint the network service running on a specific open port of a target host.

Usage:
  networkscan discover service [flags]

Flags:
  -h, --help           help for service
      --port int       Port number of the service to fingerprint (e.g., 443)
      --target string  Target IP address or hostname where the service is running
      --timeout int    Timeout in seconds for each service fingerprinting attempt (default 5)

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
      --verify-tls         Verify TLS certificates (default: true)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
