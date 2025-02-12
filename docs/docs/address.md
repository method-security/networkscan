# Address

The `networkscan address` command is used to discover and interact with network addresses.

## Usage

```bash
networkscan address [command] [flags]
```

## Commands


### Bannergrab

The `networkscan address bannergrab` grabs and analyzes the banner on a socket network address.

#### Usage

To grab the banner from a network address

```bash
networkscan address bannergrab --target scanme.sh --port 22
```

#### Help

```bash
networkscan address bannergrab -h

Grab banner from a network address

Usage:
  networkscan address bannergrab [flags]

Flags:
  -h, --help            help for bannergrab
      --port uint16     Address Port (e.g., 443)
      --target string   Target address (e.g., 192.168.1.1 or example.com)
      --timeout int     Timeout limit for each handshake in seconds (default 5)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### Bruteforce

The `networkscan address bruteforce` runs a brute force attack

#### Usage

Execute a Bruteforce attack against an application

```bash
networkscan address bruteforce  --targets 192.168.0.0:22 --module ssh
```

#### Help

```bash
networkscan address bruteforce -h

Execute a Bruteforce attack against an application

Usage:
  networkscan address bruteforce [flags]

Flags:
  -h, --help                    help for bruteforce
      --module string           Module type (ie.SSH)
      --passwordlists strings   File paths containing passwords to use in attack
      --passwords strings       Password to use in attack
      --retries int             Number of Attempts per credential pair (default 2)
      --sleep int               Sleep time between requests (Seconds) (default 3)
      --stopfirstsuccess        Stop on the first successful login
      --successfulonly          Only show successful attempts
      --targets strings         Address of target
      --timeout int             Timeout per request (Seconds) (default 3)
      --usernamelists strings   File paths containing usernames to use in attack
      --usernames strings       Username to use in attack

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

### TLS

The `networkscan address tls` checks the TLS details of a network address socket.

#### Usage

Grab the TLS Config and Certificate of a network address socket

```bash
networkscan address tls --targets example.com:443
``` 

#### Help

```bash
Grab TLS details of a network address socket

Usage:
  networkscan address tls [flags]

Flags:
  -h, --help              help for tls
      --insecure          Skip TLS verification (Default: false)
      --targets strings   Address of target
      --timeout int       Timeout limit for each handshake in seconds (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output

  ```