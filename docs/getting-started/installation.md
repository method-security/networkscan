# Getting Started

If you are just getting started with networkscan, welcome! This guide will walk you through the process of going zero to one with the tool.

## Installation

networkscan is provided as release binaries for several operating systems and architectures, as well as Docker images for amd64 and arm64.

If you do not see an architecture that you require, please open a [Discussion](https://method-security.github.io/community/contribute/discussions.html) to propose adding it.

### Binaries

networkscan currently provides binaries for the following operating systems and architectures:

| OS      | Architecture |
| ------- | ------------ |
| Linux   | amd64        |
| Linux   | arm64        |
| MacOS   | arm64        |
| Windows | amd64        |

The latest binaries can be downloaded directly from [Github](https://github.com/Method-Security/networkscan/releases/latest).

Some discovery commands require nmap. SYN port scans require raw-packet privileges; use `--scan-type CONNECT` when those privileges are unavailable. Building from source additionally requires a C compiler and libpcap development headers; see [Development Setup](../development/setup.md).

### Docker

Docker images for networkscan are hosted in both Github Container Registry as well as on Docker Hub and can be pulled via:

```bash
docker pull ghcr.io/method-security/networkscan
```

```bash
docker pull methodsecurity/networkscan
```
