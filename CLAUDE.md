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

- Use svc1log for all logging operations
- Follow existing code patterns for new protocol support
- Maintain separation between discovery, enumeration, and penetration testing
- Shared protocol libraries should be used across modules for consistency
- Configuration through Fern definitions for type safety
