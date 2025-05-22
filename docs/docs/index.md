# Capabilities

networkscan offers a variety of scanning techniques to security teams working across all cloud providers and on-premise environments. Each of the below pages offers you an in depth look at a networkscan capability related to a unique scanning technique.

- [Host](./host.md)
- [OS](./os.md)
- [Port](./port.md)
- [Service](./service.md)
- [TLS](./tls.md)
- [FTP](./ftp.md)
- [GRPC](./grpc.md)
- [SMTP](./smtp.md)
- [SSH](./ssh.md)
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
