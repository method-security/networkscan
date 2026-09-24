# NetworkScan Documentation

NetworkScan is a comprehensive network scanning and penetration testing tool that provides capabilities for discovering network resources, enumerating services, and performing security assessments.

## Available Commands

### Discover
Network discovery capabilities to identify live hosts, open ports, running services, and TLS configurations.

**Subcommands:**
- `host` - Identify live hosts within IP ranges using various discovery techniques
- `port` - Scan for open TCP ports with customizable scan types and port ranges
- `service tcp` - Fingerprint services on one or more target sockets
- `service udp` - Fingerprint common UDP services on one or more target hosts
- `tls` - Retrieve and analyze TLS configuration and certificate details
- `domain` - Discover domain information using LDAP/SMB discovery and DNS enumeration
- `route` - Trace the network path to targets
- `socket` - Connect to a socket and inspect its response

### Enumerate
Detailed enumeration of supported network services on target hosts.

**Subcommands:**
- `service` - Enumerate detailed information about [supported network services](enumerate.md#supported-services), including databases, remote-access services, directory services, and mail protocols

### Pentest
Comprehensive penetration testing capabilities including credential spraying and service-specific attacks.

**Spray Commands:**
- `spray password` - Password spraying attacks against network services (SSH, SMB, TELNET, FTP, LDAP, KERBEROS)

**Service Commands:**
- `service smb` - SMB penetration testing with authentication, command execution, share enumeration, and file downloads
- `service ssh` - SSH penetration testing with authentication, command execution, and file transfers
- `service telnet` - Telnet penetration testing with authentication and command execution
- `service ldap` - LDAP penetration testing with authentication and domain enumeration
- `service msrpc` - MS-RPC penetration testing including DCSync attacks via DRSUAPI
- `service kerberos` - Kerberos penetration testing with advanced attacks such as constrained delegation
- `service winrm`, `service rdp` - Remote management and desktop authentication testing
- `service ftp`, `service imap` - File-transfer and mailbox operations
- `service mysql`, `service postgres`, `service mssql`, `service mongodb`, `service redis`, `service oracle`, `service etcd` - Database authentication and service-specific operations
- `service dns`, `service snmp`, `service ike` - Protocol-specific security assessments

For Kerberos username enumeration, use `service kerberos --actions USER_ENUM`. Run `networkscan pentest service <service> --help` for each command's flags and available actions.

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
networkscan pentest service smb -h
```
