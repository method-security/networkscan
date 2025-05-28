# FTP

The `networkscan ftp` command is used to discover and interact with FTP on a target host.

## Usage

```bash
networkscan ftp [command] [flags]
```

## Commands


### Enumerate

The `networkscan ftp enumerate` enumerates data about FTP on a target host.

#### Usage

To enumerate data about FTP on a target host

```bash
networkscan ftp enumerate --targets 192.168.1.1:21 --timeout 30
```

#### Help

```bash
networkscan ftp enumerate -h

Enumerate data about FTP on a target host

Usage:
  networkscan ftp enumerate [flags]

Flags:
  -h, --help              help for enumerate
      --targets strings   Target IP Socket or FQDN Socket to enumerate
      --timeout int       Total time allowed for enumeration of each target in seconds (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
