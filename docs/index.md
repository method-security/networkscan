# networkscan Documentation

Hello and welcome to the networkscan documentation. While we always want to provide the most comprehensive documentation possible, we thought you may find the below sections a helpful place to get started.

- The [Getting Started](./getting-started/basic-usage.md) section provides onboarding material
- The [Development](./development/setup.md) header is the best place to get started on developing on top of and with networkscan
- See the [Docs](./docs/index.md) section for a comprehensive rundown of networkscan capabilities

# About networkscan

networkscan offers security teams comprehensive network scanning, service enumeration, and penetration testing capabilities to help them gain visibility into their cloud and on-premise environments. The tool provides advanced features including stealth scanning modes, credential spraying, service-specific attacks, and extensive protocol support. Designed with data-modeling and data-integration needs in mind, networkscan can be used on its own as an interactive CLI, orchestrated as part of a broader data pipeline, or leveraged from within the Method Platform.

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
networkscan discover port <flags>
networkscan enumerate service <flags>
networkscan pentest spray password <flags>
networkscan pentest service smb <flags>
```

#### Examples

```bash
# Network discovery
networkscan discover port --target 127.0.0.1 --ports 22,80,443
networkscan discover host --target 192.168.1.0/24

# Service enumeration
networkscan enumerate service --targets 192.168.1.10:22 --service ssh

# Penetration testing
networkscan pentest spray password --targets 192.168.1.0/24 --service SMB --usernames admin --passwords Password123
networkscan pentest service smb --targets 192.168.1.100:445 --usernames admin --passwords password --actions AUTH
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
