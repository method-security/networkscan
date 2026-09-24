# Enumerate

The `networkscan enumerate` command performs detailed enumeration of supported network services on target hosts.

## Usage

```bash
networkscan enumerate [command]
```

## Commands

### Service

Enumerate detailed information about supported network services on target hosts.

#### Usage
```bash
networkscan enumerate service --targets 127.0.0.1:22,192.168.1.101:22 --service ssh
networkscan enumerate service --targets example.com:993 --service imap
```

#### Supported Services
- `DNS` - Domain Name System enumeration
- `FTP` - File Transfer Protocol enumeration
- `GRPC` - gRPC service enumeration
- `IKE` - Internet Key Exchange enumeration
- `IMAP` - Internet Message Access Protocol enumeration
- `IPMI` - Intelligent Platform Management Interface enumeration
- `LDAP` - LDAP directory service enumeration
- `MONGODB` - MongoDB enumeration
- `MSSQL` - Microsoft SQL Server enumeration
- `MYSQL` - MySQL enumeration
- `POP3` - Post Office Protocol enumeration
- `POSTGRES` - PostgreSQL enumeration
- `RDP` - Remote Desktop Protocol enumeration
- `REDIS` - Redis enumeration
- `SMB` - Server Message Block protocol enumeration
- `SMTP` - Simple Mail Transfer Protocol enumeration
- `SNMP` - Simple Network Management Protocol enumeration
- `SOCKS` - SOCKS proxy enumeration
- `SSH` - Secure Shell protocol enumeration
- `VNC` - Virtual Network Computing enumeration

#### Help Text
```bash
networkscan enumerate service -h
Enumerate detailed information about supported network services on target hosts.

Usage:
  networkscan enumerate service [flags]

Flags:
      --dns-open-resolver-probe string   Off-zone name used to confirm recursion (DNS only, default a.root-servers.net.)
  -h, --help                             help for service
      --service string                   Service to enumerate (dns, ftp, grpc, ike, imap, ipmi, ldap, mongodb, mssql, mysql, pop3, postgres, rdp, redis, smb, smtp, snmp, socks, ssh, vnc)
      --targets strings                  List of target addresses (IP:port or hostname:port) to enumerate
      --timeout int                      Timeout in seconds for enumerating each target (default 30)
      --vnc-port-range string            Port range to sweep when no explicit port is given (VNC only, e.g. '5900-5910') (default "5900-5910")
      --vnc-skip-screenshot              Skip framebuffer screenshot capture even when None auth is offered (VNC only)
      --wordlist strings                 Custom username wordlist for user enumeration (SMTP VRFY/EXPN/RCPT TO)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --socks-proxy string   SOCKS5 proxy URL for TCP connections (e.g., socks5://127.0.0.1:1080)
  -v, --verbose              Verbose output
```
