# Protocol Implementation Provenance

The protocol implementations and parser tests in this directory are adapted
from Praetorian Security, Inc.'s Apache-2.0 licensed fingerprintx repository,
commit `48019490954a735898405a4aa304067a18d8ee7b`:
https://github.com/praetorian-inc/fingerprintx/tree/48019490954a735898405a4aa304067a18d8ee7b/pkg/plugins

Copyright 2022 Praetorian Security, Inc. The full license is in `LICENSE`.
These are locally maintained implementations, not an embedded copy of the
fingerprintx scanner or its registry. Each implements networkscan's
`Fingerprinter` interface and emits the generated Fern `ServiceDetails` type.

Networkscan adaptations include context-aware connections, TLS/SNI handling,
per-plugin timeouts, bounded HTTP reads, native protocol enums, malformed-packet
checks, and loopback integration tests. The upstream scan engine, CLI, plugin
registration, and SDK service envelope are not included.
