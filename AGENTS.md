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

### Test Layout

- **Tests live in the top-level `tests/` tree, never beside the code.** Mirror the source path with `internal/` dropped: code in `internal/enumerate/smtp/helpers.go` is tested by `tests/enumerate/smtp/helpers_test.go`. Same convention as webscan.
- Use an **external test package** — `package smtp_test`, importing the real package by its full module path.
- That means only **exported** identifiers are reachable. Export what needs testing rather than moving the test back in-package; a `_test.go` file sitting in `internal/<stage>/<component>/` is the mistake this section exists to prevent.
- `generated/**` is gitignored and its `*_test.go` files are Fern output — not the convention to copy.

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
