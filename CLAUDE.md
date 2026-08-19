# networkscan Project Context

## Overview

networkscan is a network scanning and enumeration tool that provides security teams with data-rich insights into cloud and on-premise environments. It supports multiple network discovery, service enumeration, and penetration testing capabilities.

## Architecture

The tool follows a modular architecture with clear separation of concerns:

### Core Components

1. **Discovery Module** (`internal/discover/`)
   - Host discovery and OS fingerprinting
   - Port scanning using nmap/naabu integration
   - Service detection and fingerprinting
   - TLS certificate analysis

2. **Enumeration Module** (`internal/enumerate/`)
   - Protocol-specific service enumeration
   - Supported services: SSH, SMB, SMTP, FTP, gRPC
   - Detailed service configuration extraction
   - Banner grabbing and version detection

3. **Penetration Testing Module** (`internal/pentest/`)
   - Service-specific authentication testing (SMB, SSH, Telnet)
   - Command execution capabilities  
   - Protocol-specific attack vectors
   - Credential validation and enumeration

4. **Protocol Libraries** (`internal/protocol/`)
   - Shared protocol implementations (SMB, etc.)
   - Unified client libraries for consistent behavior
   - NTLM authentication handling

### CLI Structure (`cmd/`)
- `root.go` - Main CLI setup with Cobra
- `discover.go` - Discovery command implementations
- `enumerate.go` - Enumeration command implementations  
- `pentest.go` - Penetration testing command implementations

### Generated Code (`generated/go/`)
- Fern-generated Go types and clients
- Protocol definitions and data structures
- API interfaces for type safety

### Configuration Management
- Wordlist management (`configs/pentest/`)
- Service-specific configuration files
- Default credential lists

## Project Structure

- **Language**: Go
- **Module**: github.com/method-security/networkscan
- **CLI Framework**: Cobra
- **Type Generation**: Fern
- **Logging**: svc1log (witchcraft-go-logging)
- **Testing**: Standard Go testing + external tool integration

## Key Features

- Multi-protocol network scanning (TCP/UDP)
- Service enumeration with deep inspection
- Service-specific penetration testing (SMB, SSH, Telnet)
- Authentication testing with intelligent domain handling
- Command execution and privilege validation
- TLS certificate analysis
- Structured output in multiple formats (JSON, etc.)
- Docker containerization support
- Integration with Method Security platform

## Development Patterns

### CLI Development Conventions
- Follow the CLI Development Conventions for attack stage organization
- Use `<stage>Cmd` in camelCase for top-level commands (e.g., `discoverCmd`)
- Use `<stage><Component>Cmd` for subcommands (e.g., `discoverHostCmd`)
- Implement Run functions with action verbs (e.g., `RunHostDiscovery`, `RunPortScan`)

### Flag Naming and Handling
- Use kebab-case for CLI flags: `--scan-type`
- Use camelCase when extracting flags: `scanType, err := cmd.Flags().GetString("scan-type")`
- Always check errors when extracting flags:
  ```go
  if err != nil {
      a.OutputSignal.AddError(err)
      return
  }
  ```
- Use `.GetStringSlice` for slice inputs with plural flag names
- Mark required flags explicitly: `_ = cmd.MarkFlagRequired("target")`

### Code Organization
- Repository organized by attack stage (`discover`, `enumerate`, `pentest`)
- Mirror naming between `fern/definition/<stage>/<component>.yml`, `internal/<stage>/<component>.go`, and `cmd/<stage>.go`
- Use subdirectories for complex components, flat files for simple ones

### Fern Type Requirements
- **MANDATORY**: Every CLI command with output must have a corresponding Fern report structure
- **Three-Part Structure Pattern**: All commands must define:
  ```yaml
  # 1. Config type for input parameters
  <Stage><Component>Config:
    properties:
      # Command-specific configuration parameters
      target: string
      timeout: optional<integer>
  
  # 2. Result type for output data
  <Stage><Component>Result:
    properties:
      # Command-specific result data
      hosts: optional<list<HostDetail>>
      services: optional<list<ServiceDetail>>
  
  # 3. Report type wrapping config, result, and errors
  <Stage><Component>Report:
    properties:
      config: <Stage><Component>Config
      result: <Stage><Component>Result
      errors: optional<list<string>>
  ```
- **Example Implementation**:
  ```yaml
  DiscoverTlsConfig:
    properties:
      target: string
      timeout: integer
      insecureSkipVerify: boolean
  
  DiscoverTlsResult:
    properties:
      tlsDetails: optional<list<TlsDetail>>
  
  DiscoverTlsReport:
    properties:
      config: DiscoverTlsConfig
      result: DiscoverTlsResult
      errors: optional<list<string>>
  ```
- **Type Organization**: Follow the CLI Development Conventions type ordering:
  1. ENUMs (e.g., `TlsVersion`, `ScanType`)
  2. Common Objects (e.g., `Certificate`, `ServiceDetail`)
  3. Config Types (e.g., `DiscoverTlsConfig`)
  4. Result Types (e.g., `DiscoverTlsResult`)
  5. Report Types (e.g., `DiscoverTlsReport`)

### Development Commands
```bash
# MANDATORY: Run after completing TODOs to ensure code can be merged
./godelw verify

# Build the binary
./godelw build
```

### General Patterns
- Use svc1log for all logging operations
- Follow existing code patterns for new protocol support
- Maintain separation between discovery, enumeration, and penetration testing
- Shared protocol libraries should be used across modules for consistency
- Configuration through Fern definitions for type safety
- **CRITICAL**: Always run `./godelw verify` after TODO completion before merging

## CVE Detection — Two Execution Paths, One Report

`pentest cve` runs **both** nuclei templates and custom Go detectors and merges them into the same `PentestCveReport`. This mirrors `discover service`, where fingerprintx and custom protocol plugins both feed the same `ServiceDetails` type. Downstream processors don't care which path produced an attempt — the report shape is identical.

| Path | Lives in | Use when |
|------|----------|----------|
| Nuclei template | `utils/nuclei/templates/cve/<year>/...` | A working nuclei template exists or can be written. Default — easier to maintain. |
| Custom Go detector | `internal/pentest/cve/detectors/cve_<year>_<id>.go` | Detection requires Go code that nuclei cannot express: stateful protocols, custom binary probes, multi-step handshakes, library-driven checks (SMB/Kerberos/etc.), or anything that needs internal helpers in `internal/protocol/`. |

### Adding a custom CVE detector

1. **Create the file** — `internal/pentest/cve/detectors/cve_<year>_<id>.go`, package `detectors`. Type name `CVE_<year>_<id>` (underscores). See `internal/pentest/cve/detectors/doc.go` for the skeleton.
2. **Implement the `cve.Detector` interface** (defined in `internal/pentest/cve/detector.go`):
   - `CVEID()` → canonical ID matching `^CVE-\d{4}-\d{4,}$` (the report builder regexes on this).
   - `Year()` → 4-digit string; used by the `--years` CLI filter exactly like nuclei template years.
   - `Protocol()` → uppercase token (`"SSH"`, `"FTP"`, `"HTTP"`, …) matching the `--protocol` filter; empty means "any protocol".
   - `Detect(ctx, target, timeout)` → returns `*nuclei.NucleiAttemptInfo` with `TemplateId == CVEID()`. Return semantics:
     - Vulnerable → attempt with `Finding.Finding = true` and populated `NucleiFindingInfo` (Name, Description, Severity, `Classification.Cves`).
     - Probed-but-clean → attempt with `Finding.Finding = false`.
     - Service didn't match → `(nil, nil)`.
     - Fatal probe error → `(nil, err)` — surfaced as a warning, not an error.
3. **Register it** — append a pointer to the type in `registeredDetectors` in `internal/pentest/cve/registry.go`.
4. **Verify** — `./godelw verify`. No new Fern types are needed; the existing `nuclei.NucleiAttemptInfo` shape is what custom detectors produce.

### Rules

- **One detector per CVE.** Don't bundle multiple CVEs into one type; the year/protocol filters and the per-CVE TemplateId rely on the 1-to-1 mapping.
- **Don't bypass filters.** Always declare a real `Year()` and `Protocol()`. If the detector legitimately works against any protocol, return `""` for `Protocol()` and document why in a one-line comment.
- **Reuse existing protocol clients** from `internal/protocol/` and `internal/common/` before writing new probe code.
- **Don't add CLI flags.** The custom path uses the existing `--targets / --protocol / --years / --timeout` flags. New knobs that don't fit those filters mean the check probably belongs somewhere other than `pentest cve`.
- **No silent drift between paths.** If you change the `NucleiAttemptInfo` / `NucleiFindingInfo` Fern shape, both paths must keep producing it identically. Run a real `pentest cve` against a known target and inspect the JSON before opening a PR.
- **`--template-paths` skips custom detectors.** When the operator passes `--template-paths`, the orchestrator runs only those nuclei templates and the custom detector registry is skipped entirely — matching how that flag turns off `--years` and `--protocol` for nuclei.
