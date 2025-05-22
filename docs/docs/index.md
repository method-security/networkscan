# Capabilities

networkscan organizes its functionality into modules. Each module groups a set of related commands used during different phases of a network assessment.

## Discover

- [Host](./host.md)
- [OS](./os.md)
- [Port](./port.md)
- [Address](./address.md)

## Enumerate

- [FTP](./ftp.md)
- [SMTP](./smtp.md)
- [SSH](./ssh.md)

## Pentest

- [Bruteforce](./bruteforce.md)

## Top Level Flags

networkscan has several top level flags that can be used on any subcommand. These include:

```bash
Flags:
  -h, --help                 help for networkscan
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

## Version Command

Run `networkscan version` to get the exact version information for your binary

## Output Formats

For more information on the various output formats that are supported by networkscan, see the [Output Formats](https://method-security.github.io/docs/output.html) page in our organization wide documentation.
