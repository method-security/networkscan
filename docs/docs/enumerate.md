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
networkscan enumerate service --targets 127.0.0.1:22,192.168.1.101:21 --service ssh
```

#### Help Text
```bash
networkscan enumerate service -h
Enumerate detailed information about supported network services on target hosts.

Usage:
  networkscan enumerate service [flags]

Flags:
  -h, --help               help for service
      --service string     Service to enumerate (ftp, grpc, smtp, ssh)
      --targets strings    List of target addresses (IP:port or hostname:port) to enumerate
      --timeout int        Timeout in seconds for enumerating each target (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
