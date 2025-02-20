# SSH

The `networkscan ssh` command is used to discover and interact with SSH on a target host.

## Usage

```bash
networkscan ssh [command] [flags]
```

## Commands


### Enumerate

The `networkscan ssh enumerate` enumerates data about SSH on a target host.

#### Usage

To enumerate data about SSH on a target host

```bash
networkscan ssh enumerate --targets 192.168.1.1:22 --timeout 30
```

#### Help

```bash
networkscan ssh enumerate -h

Enumerate data about SSH on a target host

Usage:
  networkscan ssh enumerate [flags]

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
