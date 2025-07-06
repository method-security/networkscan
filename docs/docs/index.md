# NetworkScan Documentation

NetworkScan is a comprehensive network scanning and penetration testing tool that provides capabilities for discovering network resources, enumerating services, and performing security assessments.

## Available Commands

### Discover
Network discovery capabilities to identify live hosts, open ports, running services, and TLS configurations.

**Subcommands:**
- `host` - Identify live hosts within IP ranges using various discovery techniques
- `os` - Detect and fingerprint operating systems (requires nmap and root privileges)
- `port` - Scan for open TCP ports with customizable scan types and port ranges
- `service` - Identify and fingerprint network services on specific ports
- `tls` - Retrieve and analyze TLS configuration and certificate details

### Enumerate
Detailed enumeration of supported network services on target hosts.

**Subcommands:**
- `service` - Enumerate detailed information about supported network services (ftp, grpc, smtp, ssh)

### Pentest
Penetration testing modules against network services.

**Subcommands:**
- `service` - Run penetration testing modules against network services
  - `bruteforce` - Perform brute-force attacks against specified service modules

## Global Flags

All commands support the following global flags:

- `-o, --output string` - Output format (signal, json, yaml). Default value is signal (default "signal")
- `-f, --output-file string` - Path to output file. If blank, will output to STDOUT
- `-q, --quiet` - Suppress output
- `-v, --verbose` - Verbose output

## Getting Help

For help with any command, use the `-h` or `--help` flag:

```bash
networkscan -h
networkscan discover -h
networkscan enumerate service -h
networkscan pentest service bruteforce -h
```
