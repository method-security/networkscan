// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package ftp

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"time"

	probe "github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	utils "github.com/Method-Security/networkscan/internal/discover/service/probes/wireio"
)

// FTP protocol constants
const (
	FTP                  = "ftp"
	DefaultFTPPort       = 21
	FTPWelcomeResponseRe = `^220[- ]` // FTP 220 response code (service ready)
)

// FTP keyword whitelist pattern - matches FTP, FTPD, "FTP server", "FTP service" (case-insensitive)
// This is the core of the whitelist approach to prevent SMTP false positives (PR #44 fix)
var ftpKeywordPattern = regexp.MustCompile(`(?i)(ftpd?|ftp\s+(server|service))`)

// ftpWelcomePattern matches FTP 220 welcome responses
var ftpWelcomePattern = regexp.MustCompile(FTPWelcomeResponseRe)

// Version extraction patterns for known FTP servers (requires version in banner)
var versionPatterns = []struct {
	server  string
	pattern *regexp.Regexp
}{
	{"vsftpd", regexp.MustCompile(`\(vsFTPd\s+([0-9.]+)\)`)},
	{"ProFTPD", regexp.MustCompile(`ProFTPD\s+([0-9.]+[a-z]?)\s+Server`)},
	{"Pure-FTPd", regexp.MustCompile(`(?i)Pure-?FTPd\s+([0-9.]+)`)},
	{"FileZilla", regexp.MustCompile(`FileZilla Server version\s+([0-9.]+)`)},
	{"Microsoft IIS", regexp.MustCompile(`Microsoft FTP Service\s*\(Version\s+([0-9.]+)\)`)},
	{"wu-ftpd", regexp.MustCompile(`Version wu-([0-9.-]+)`)},
	{"Generic", regexp.MustCompile(`Version\s+([0-9.]+)`)},
}

// Server identification patterns (no version required, used as fallback)
var serverPatterns = []struct {
	server  string
	pattern *regexp.Regexp
}{
	{"vsftpd", regexp.MustCompile(`(?i)vsFTPd`)},
	{"ProFTPD", regexp.MustCompile(`(?i)ProFTPD`)},
	{"Pure-FTPd", regexp.MustCompile(`(?i)Pure-?FTPd`)},
	{"FileZilla", regexp.MustCompile(`(?i)FileZilla`)},
	{"Microsoft IIS", regexp.MustCompile(`(?i)Microsoft FTP`)},
	{"wu-ftpd", regexp.MustCompile(`(?i)wu-[0-9]`)},
}

// CPE vendor mappings for known FTP servers
var cpeVendors = map[string]string{
	"vsftpd":        "cpe:2.3:a:vsftpd:vsftpd:%s:*:*:*:*:*:*:*",
	"ProFTPD":       "cpe:2.3:a:proftpd:proftpd:%s:*:*:*:*:*:*:*",
	"Pure-FTPd":     "cpe:2.3:a:pureftpd:pure-ftpd:%s:*:*:*:*:*:*:*",
	"FileZilla":     "cpe:2.3:a:filezilla-project:filezilla_server:%s:*:*:*:*:*:*:*",
	"Microsoft IIS": "cpe:2.3:a:microsoft:ftp_service:%s:*:*:*:*:*:*:*",
}

type FTPPlugin struct{}

// isFTPBanner determines if a banner indicates FTP service and returns confidence level.
// Detection strategy (whitelist approach):
//   - HIGH confidence: Port 21 + FTP keyword match
//   - MEDIUM confidence: Non-standard port + FTP keyword match
//   - LOW confidence: Port 21 + No FTP keyword (heuristic fallback)
//   - REJECT: No detection if no FTP keywords on non-21 ports (prevents SMTP false positives)
//
// Parameters:
//   - banner: The server banner string
//   - port: The port number being scanned
//
// Returns:
//   - bool: true if FTP detected, false otherwise
//   - string: confidence level ("high", "medium", "low", or "" if rejected)
func isFTPBanner(banner string, port uint16) (bool, string) {

	if ftpKeywordPattern.MatchString(banner) {
		if port == DefaultFTPPort {
			return true, "high"
		}
		return true, "medium"
	}

	if port == DefaultFTPPort && ftpWelcomePattern.MatchString(banner) {
		return true, "low"
	}

	return false, ""
}

// extractFTPVersion extracts FTP server type and version from banner.
// Attempts to match against known FTP server patterns in order of specificity.
// If version cannot be extracted but server is identified, returns server with empty version.
//
// Parameters:
//   - banner: The FTP banner string
//
// Returns:
//   - string: Server type (e.g., "vsftpd", "ProFTPD") or empty if not found
//   - string: Version string (e.g., "2.0.1") or empty if not found
func extractFTPVersion(banner string) (string, string) {

	for _, vp := range versionPatterns {
		matches := vp.pattern.FindStringSubmatch(banner)
		if len(matches) >= 2 {
			return vp.server, matches[1]
		}
	}

	for _, sp := range serverPatterns {
		if sp.pattern.MatchString(banner) {
			return sp.server, ""
		}
	}

	return "", ""
}

// buildFTPCPE generates a CPE (Common Platform Enumeration) string for FTP servers.
// CPE format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
//
// When version is unknown but server is identified, uses "*" for version field
// to match Wappalyzer/RMI plugin behavior and enable asset inventory use cases.
//
// Parameters:
//   - server: Server type (e.g., "vsftpd", "ProFTPD")
//   - version: Version string (e.g., "2.0.1"), or empty for unknown
//
// Returns:
//   - string: CPE string, or empty if server is unknown
func buildFTPCPE(server, version string) string {
	if server == "" {
		return ""
	}
	if version == "" {
		version = "*"
	}

	cpeTemplate, exists := cpeVendors[server]
	if !exists {
		return ""
	}

	return fmt.Sprintf(cpeTemplate, version)
}
func (p *FTPPlugin) Run(conn net.Conn, timeout time.Duration, target probe.Target) (*probe.Service, error) {
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	banner := string(response)

	port := target.Address.Port()
	detected, confidence := isFTPBanner(banner, port)
	if !detected {
		return nil, nil
	}

	server, version := extractFTPVersion(banner)
	cpe := buildFTPCPE(server, version)

	payload := probe.ServiceFTP{
		Banner:     banner,
		Confidence: confidence,
	}

	if cpe != "" {
		payload.CPEs = []string{cpe}
	}

	return probe.Result(target, payload, false, version, probe.TCP), nil
}
func (p *FTPPlugin) PortPriority(i uint16) bool {
	return i == DefaultFTPPort
}
func (p *FTPPlugin) Name() string {
	return FTP
}
func (p *FTPPlugin) Type() probe.Protocol {
	return probe.TCP
}
func (p *FTPPlugin) Priority() int {
	return 10
}

var defaultFTPPluginPorts = probe.Ports((&FTPPlugin{}).PortPriority)

func (p *FTPPlugin) DefaultPorts() []int { return defaultFTPPluginPorts }
func (p *FTPPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*probe.Service, error) {
	return probe.Detect(ctx, ip, port, host, timeout, p.Name(), p.Type(), p.Run)
}
