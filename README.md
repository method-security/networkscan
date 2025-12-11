<div align="center">
<h1>networkscan</h1>

[![GitHub Release][release-img]][release]
[![Verify][verify-img]][verify]
[![Go Report Card][go-report-img]][go-report]
[![License: Apache-2.0][license-img]][license]
[![Acceptable Use Policy][acceptable-use-policy-img]][acceptable-use-policy]

[![GitHub Downloads][github-downloads-img]][release]
[![Docker Pulls][docker-pulls-img]][docker-pull]

</div>

networkscan offers security teams comprehensive network scanning, service enumeration, and penetration testing capabilities to help them gain visibility into their cloud and on-premise environments. The tool provides advanced features including stealth scanning modes, credential spraying, service-specific attacks, and extensive protocol support. Designed with data-modeling and data-integration needs in mind, networkscan can be used on its own as an interactive CLI, orchestrated as part of a broader data pipeline, or leveraged from within the Method Platform.

## Key Features

- **Network Discovery**: Host discovery with multiple scan types, port scanning with stealth modes, service fingerprinting for TCP/UDP protocols
- **Service Enumeration**: Deep inspection of network services including SSH, SMB, LDAP, SMTP, FTP, and gRPC
- **Penetration Testing**: Credential spraying against multiple protocols, service-specific attacks, and advanced techniques like DCSync and Kerberos delegation
- **Stealth Operations**: Configurable delays, jitter, and evasion techniques across all scanning modes
- **Built-in Wordlists**: Integrated username and password lists for common attack scenarios
- **Flexible Output**: Multiple output formats (JSON, YAML, Signal) with structured reporting

The types of scans that networkscan can conduct are constantly growing. For the most up to date listing, please see the documentation [here](./docs/index.md)

To learn more about networkscan, please see the [Documentation site](https://method-security.github.io/networkscan/) for the most detailed information.

## Quick Start

### Get networkscan

For the full list of available installation options, please see the [Installation](./getting-started/installation.md) page. For convenience, here are some of the most commonly used options:

- `docker run methodsecurity/networkscan`
- `docker run ghcr.io/method-security/networkscan`
- Download the latest binary from the [Github Releases](https://github.com/Method-Security/networkscan/releases/latest) page
- [Installation documentation](./getting-started/installation.md)

### General Usage

```bash
networkscan [command] [subcommand] <flags>
```

#### Examples

```bash
# Network Discovery
networkscan discover host --target 192.168.1.0/24
networkscan discover host --target 192.168.1.0/24 --sleep 2 --jitter 10 --reverse-lookup
networkscan discover port --target scanme.sh --top-ports 100
networkscan discover port --target scanme.sh --ports 22,80,443 --validate
networkscan discover service --target scanme.sh:22
networkscan discover service --target 192.168.1.1 --udp
networkscan discover tls --targets scanme.sh:443,example.com:443
networkscan discover domain --target 192.168.1.1

# Service Enumeration  
networkscan enumerate service --targets 192.168.1.10:22,192.168.1.11:21 --service ssh

# Credential Spraying
networkscan pentest spray password --targets 192.168.1.0/24 --service SMB --usernames admin,guest --passwords Password123,123456 --domain CORP
networkscan pentest spray password --targets 192.168.1.100:445 --service SMB --username-lists DOMAIN_USERNAMES --password-lists DOMAIN_PASSWORDS --sleep 2 --jitter 10
networkscan pentest spray username --targets dc.example.com:88 --service KERBEROS --domain EXAMPLE.COM --usernames admin,guest

# Service-Specific Penetration Testing
networkscan pentest service smb --targets 192.168.1.100:445 --usernames admin --passwords password --actions AUTH,SHARES_MAP
networkscan pentest service ssh --targets 192.168.1.100:22 --usernames root --passwords password --actions AUTH,EXEC --execute "whoami"
networkscan pentest service telnet --targets 192.168.1.100:23 --usernames admin --passwords password --actions AUTH
networkscan pentest service ldap --targets dc.example.com:389 --usernames user --passwords pass --domain EXAMPLE.COM --actions AUTH,DOMAINDUMP
networkscan pentest service msrpc --targets dc.example.com:445 --usernames admin --passwords Password123 --domain EXAMPLE.COM --actions DCSYNC
networkscan pentest service kerberos --targets dc.example.com:88 --usernames user --passwords pass --domain EXAMPLE.COM --actions SERVICE_TICKET --spn HTTP/server.example.com
```

## Contributing

Interested in contributing to networkscan? Please see our organization wide [Contribution](https://method-security.github.io/community/contribute/discussions.html) page.

## Want More?

If you're looking for an easy way to tie networkscan into your broader cybersecurity workflows, or want to leverage some autonomy to improve your overall security posture, you'll love the broader Method Platform.

For more information, visit us [here](https://method.security)

## Community

networkscan is a Method Security open source project.

Learn more about Method's open source source work by checking out our other projects [here](https://github.com/Method-Security) or our organization wide documentation [here](https://method-security.github.io).

Have an idea for a Tool to contribute? Open a Discussion [here](https://github.com/Method-Security/Method-Security.github.io/discussions).

[verify]: https://github.com/Method-Security/networkscan/actions/workflows/verify.yml
[verify-img]: https://github.com/Method-Security/networkscan/actions/workflows/verify.yml/badge.svg
[go-report]: https://goreportcard.com/report/github.com/Method-Security/networkscan
[go-report-img]: https://goreportcard.com/badge/github.com/Method-Security/networkscan
[release]: https://github.com/Method-Security/networkscan/releases
[releases]: https://github.com/Method-Security/networkscan/releases/latest
[release-img]: https://img.shields.io/github/release/Method-Security/networkscan.svg?logo=github
[github-downloads-img]: https://img.shields.io/github/downloads/Method-Security/networkscan/total?logo=github
[docker-pulls-img]: https://img.shields.io/docker/pulls/methodsecurity/networkscan?logo=docker&label=docker%20pulls%20%2F%20networkscan
[docker-pull]: https://hub.docker.com/r/methodsecurity/networkscan
[license]: https://github.com/Method-Security/networkscan/blob/main/LICENSE
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[acceptable-use-policy]: https://github.com/Method-Security/networkscan/blob/main/ACCEPTABLE_USE_POLICY.md
[acceptable-use-policy-img]: https://www.svgrepo.com/show/497211/judge.svg