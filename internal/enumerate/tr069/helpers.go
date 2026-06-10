package tr069

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// parseRomPagerVersion extracts the version number from a RomPager Server header.
// Returns the version string (e.g. "4.07") or "" if not a RomPager header.
func parseRomPagerVersion(serverHeader string) string {
	// Matches "RomPager/4.07" or "RomPager/4.07 UPnP/1.0"
	re := regexp.MustCompile(`(?i)RomPager/([0-9]+\.[0-9]+)`)
	m := re.FindStringSubmatch(serverHeader)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// isVulnerableRomPager returns true if the version string is below romPagerVulnVersion.
func isVulnerableRomPager(version string) bool {
	parts := strings.SplitN(version, ".", 2)
	if len(parts) != 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	vulnParts := strings.SplitN(romPagerVulnVersion, ".", 2)
	vulnMajor, _ := strconv.Atoi(vulnParts[0])
	vulnMinor, _ := strconv.Atoi(vulnParts[1])
	return major < vulnMajor || (major == vulnMajor && minor < vulnMinor)
}

// isMiraiDTClass returns true if the server header matches known Mirai DT-class patterns.
func isMiraiDTClass(serverHeader string) bool {
	for _, p := range miraiDTPatterns {
		if strings.Contains(serverHeader, p) {
			return true
		}
	}
	return false
}

// detectCWMPVersion scans a response body for known CWMP namespace URIs and returns
// the highest version found. The list is checked newest-first so the first match is
// the highest supported version, avoiding nondeterminism from map iteration.
//
// To avoid false positives from servers that echo the request body verbatim, a
// namespace match is only accepted when the body also contains at least one element
// name that can only appear in a genuine CWMP response (not in the probe itself).
func detectCWMPVersion(body string) string {
	if !hasCWMPResponseElement(body) {
		return ""
	}
	for _, entry := range cwmpVersionNamespaces {
		if strings.Contains(body, entry.namespace) {
			return entry.version
		}
	}
	return ""
}

// hasCWMPResponseElement returns true when the body contains at least one XML element
// name that is exclusive to CWMP server responses.  These names do not appear in the
// GetRPCMethods probe that we send, so their presence proves the body is a real reply
// and not a simple echo of our request.
func hasCWMPResponseElement(body string) bool {
	for _, indicator := range cwmpResponseIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}
	return false
}

// parseAuthRealm extracts the Basic Auth realm from a WWW-Authenticate header.
func parseAuthRealm(header string) string {
	re := regexp.MustCompile(`(?i)realm="([^"]*)"`)
	m := re.FindStringSubmatch(header)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// isBasicAuth returns true if the WWW-Authenticate header requests Basic auth.
func isBasicAuth(header string) bool {
	return strings.Contains(strings.ToLower(header), "basic")
}

// buildHTTPClient creates an HTTP client that does NOT follow redirects.
func buildHTTPClient(transport *http.Transport) *http.Client {
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
