<div align="center">
<h1>networkscan</h1>

[![GitHub Release][release-img]][release]
[![Verify][verify-img]][verify]
[![Go Report Card][go-report-img]][go-report]
[![License: Apache-2.0][license-img]][license]

[![GitHub Downloads][github-downloads-img]][release]
[![Docker Pulls][docker-pulls-img]][docker-pull]

</div>

networkscan offers security teams a data-rich network scanning and enumeration techniques to help them gain visibility into all of their cloud and on-premise environments. Designed with data-modeling and data-integration needs in mind, networkscan can be used on its own as an interactive CLI, orchestrated as part of a broader data pipeline, or leveraged from within the Method Platform.

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
```

#### Examples

```bash
networkscan discover port --top-ports 100 --targets scanme.sh
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
