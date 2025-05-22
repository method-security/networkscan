# Bruteforce

The `networkscan pentest bruteforce` command attempts to authenticate against supported services using provided username and password combinations.

## Usage

Execute a bruteforce attack against a service:

```bash
networkscan pentest bruteforce --targets 192.168.0.1:22 --module ssh
```

## Help

```bash
networkscan pentest bruteforce -h

Perform a brute-force attack against a specified service module (e.g., SSH, FTP) using provided credentials.

Usage:
  networkscan pentest bruteforce [flags]

Flags:
  -h, --help               help for bruteforce
      --targets strings    List of target addresses (IP:port or hostname:port) to attack
      --module string      Type of service module to attack (e.g., SSH, FTP, etc.)
      --usernames strings  List of usernames to use in the brute-force attack
      --username-lists strings   File paths containing lists of usernames (one per line) to use in the attack
      --passwords strings  List of passwords to use in the brute-force attack
      --password-lists strings   File paths containing lists of passwords (one per line) to use in the attack
      --timeout int        Timeout per authentication attempt in milliseconds (default 3000)
      --sleep int          Sleep duration in milliseconds between authentication attempts (default 3000)
      --retries int        Number of retry attempts per username/password pair (default 2)
      --successful-only    Display only successful authentication attempts in the output
      --stop-first-success Stop the brute-force attack after the first successful login

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
