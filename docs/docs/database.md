# Database

The `networkscan database` command is used to discover and interact with databases on a target host.

## Usage

```bash
networkscan database [command] [flags]
```

## Commands


### MySQL

The `networkscan database mysql` command is used to discover and interact with MySQL databases on a target host.

#### Usage

```bash
networkscan database mysql [command] [flags]
```

##### Commands

###### Enumerate

To enumerate data about MySQL on a target host

```bash
networkscan database mysql enumerate --targets 192.168.1.1:3306 --timeout 30
```

#### Help

```bash
networkscan database mysql enumerate -h

Enumerate data about MySQL on a target host

Usage:
  networkscan database mysql enumerate [flags]

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
