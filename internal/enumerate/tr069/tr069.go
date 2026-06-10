// Package tr069 provides TR-069/CWMP service enumeration functionality.
package tr069

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	commonProtocol "github.com/Method-Security/networkscan/generated/go/common/protocol"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	tr069Fern "github.com/Method-Security/networkscan/generated/go/enumerate/tr069"
	"github.com/Method-Security/networkscan/utils"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LibraryEnumerateTR069 implements NetworkApplicationLibrary for TR-069/CWMP enumeration.
// It probes port 7547 (or a configured port) to identify CWMP-speaking CPE devices and
// fingerprint them via HTTP headers and SOAP response analysis.
type LibraryEnumerateTR069 struct{}

// EnumerateTarget connects to a TR-069 endpoint, sends a GetRPCMethods SOAP probe,
// and returns structured details about the CWMP service.
func (t *LibraryEnumerateTR069) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting TR-069 enumeration", svc1log.SafeParam("target", target))

	details := tr069Fern.EnumerateTr069Details{Target: target}
	var errors []string

	host, port := utils.ParseHostPort(target, defaultTr069Port)
	if host == "" {
		errors = append(errors, fmt.Sprintf("invalid target %q: could not parse host:port", target))
		return &enumeratefern.EnumerateServiceDetails{EnumerateTr069Details: &details}, errors
	}

	addr := utils.FormatHostPort(host, port)
	details.Target = addr

	// Abort immediately if the context has already expired.
	if err := ctx.Err(); err != nil {
		return &enumeratefern.EnumerateServiceDetails{EnumerateTr069Details: &details},
			[]string{fmt.Sprintf("context expired before probe started: %v", err)}
	}

	// Derive timeout from context deadline; fall back to the internal default.
	timeout := time.Duration(defaultTimeoutMs) * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 {
			timeout = remaining
		}
	}

	// Step 1: TCP reachability check.
	// Use a capped fraction of the total timeout so a slow TCP handshake cannot
	// starve the SOAP probes.  DialContext honours context cancellation.
	tcpTimeout := timeout / 4
	if tcpTimeout > 3*time.Second {
		tcpTimeout = 3 * time.Second
	}
	conn, err := (&net.Dialer{Timeout: tcpTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		portOpen := false
		details.PortOpen = &portOpen
		errors = append(errors, fmt.Sprintf("TCP connection failed: %v", err))
		return &enumeratefern.EnumerateServiceDetails{EnumerateTr069Details: &details}, errors
	}
	_ = conn.Close()

	portOpen := true
	details.PortOpen = &portOpen

	// Step 2: Send SOAP GetRPCMethods probe over HTTP (and optionally HTTPS)
	//
	// Re-derive per-probe timeout from the live context deadline NOW, after the
	// TCP check has completed.  Using the initial `timeout` snapshot would
	// overstate the available budget because it predates the TCP handshake.
	// Dividing the remaining time equally across schemes ensures both HTTP and
	// HTTPS each get a fair share without exceeding the per-target deadline.
	schemes := []string{"http", "https"}
	probeTimeout := timeout / time.Duration(len(schemes)) // default if no deadline
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 {
			probeTimeout = remaining / time.Duration(len(schemes))
		}
	}
	if probeTimeout < time.Second {
		probeTimeout = time.Second
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: probeTimeout,
		}).DialContext,
		TLSHandshakeTimeout: probeTimeout,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // CPE certs are often self-signed
		},
	}
	client := buildHTTPClient(transport)

	// Try HTTP first, then HTTPS if HTTP returns a non-CWMP response.
	// A response is considered CWMP-specific if it carries a Server header,
	// a detectable CWMP version, or known vulnerability signatures.
	// If no scheme yields CWMP-specific info, probe errors are surfaced to callers.
	var serverInfo *commonProtocol.Tr069ServerInfo
	var rawResp string
	var probeErrs []string
	// anyProbeSucceeded tracks whether at least one scheme returned an HTTP
	// response (no transport error), even if the response carried no CWMP
	// indicators.  Used below to distinguish "host unreachable on both schemes"
	// from "host responded but isn't CWMP".
	var anyProbeSucceeded bool

	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s%s", scheme, addr, cwmpEndpoint)
		si, raw, probeErr := probeCWMP(ctx, client, url, probeTimeout, log)
		if probeErr != nil {
			log.Info("CWMP probe failed", svc1log.SafeParam("scheme", scheme), svc1log.SafeParam("error", probeErr.Error()))
			probeErrs = append(probeErrs, fmt.Sprintf("%s: %v", scheme, probeErr))
			continue
		}
		anyProbeSucceeded = true
		// Only overwrite saved data if the new result has at least one field populated,
		// so a sparse HTTPS result never erases richer HTTP fingerprint data.
		// si is nil when probeCWMP found no CWMP-indicative fields (Bug 2 fix).
		if si != nil && (si.HttpServer != nil || si.CwmpVersion != nil || len(si.KnownVulnSignatures) > 0 ||
			si.ConnectionRequestAuthRequired != nil || si.ConnectionRequestRealm != nil) {
			serverInfo = si
			rawResp = raw
			// Stop probing — any CWMP-indicative signal (server banner, version, auth
			// hints, or vuln signatures) means we are talking to a TR-069 endpoint.
			// HTTPS fallback is reserved for endpoints where HTTP returns nothing at all.
			break
		}
		// HTTP gave no CWMP-indicative data; keep probing (HTTPS may be more useful).
		// Save as a fallback only if we have nothing yet.
		if rawResp == "" {
			rawResp = raw
		}
	}

	// Only report a probing failure when no scheme could establish HTTP contact
	// at all (all probes hit transport errors).  If any probe got a response —
	// even one with no CWMP indicators — the host answered and we should not
	// misreport it as unreachable.
	if !anyProbeSucceeded && len(probeErrs) > 0 {
		errors = append(errors, fmt.Sprintf("CWMP probing failed: %s", strings.Join(probeErrs, "; ")))
	}

	if serverInfo != nil {
		details.ServerInfo = serverInfo
	}
	if rawResp != "" {
		details.RawResponse = &rawResp
	}

	return &enumeratefern.EnumerateServiceDetails{EnumerateTr069Details: &details}, errors
}

// probeCWMP sends a SOAP GetRPCMethods request and parses the response.
func probeCWMP(ctx context.Context, client *http.Client, url string, timeout time.Duration, log svc1log.Logger) (*commonProtocol.Tr069ServerInfo, string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewBufferString(soapGetRPCMethods))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", soapContentType)
	req.Header.Set("SOAPAction", `""`)
	req.Header.Set("User-Agent", "MethodSecurity/1.0 TR-069-Probe")

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	// Read first 4096 bytes for analysis (don't consume entire body on slow CPE)
	buf := make([]byte, 4096)
	n, _ := io.ReadAtLeast(resp.Body, buf, 1)
	bodySnip := string(buf[:n])

	// Drain remaining body to allow connection reuse
	_, _ = io.Copy(io.Discard, resp.Body)

	si := &commonProtocol.Tr069ServerInfo{}

	// Extract HTTP Server header
	if sv := resp.Header.Get("Server"); sv != "" {
		si.HttpServer = &sv
	}

	// Connection-request auth shape
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth != "" {
		authRequired := true
		si.ConnectionRequestAuthRequired = &authRequired

		if isBasicAuth(wwwAuth) {
			realm := parseAuthRealm(wwwAuth)
			if realm != "" {
				si.ConnectionRequestRealm = &realm
			}
		}
	} else {
		// 401 with no WWW-Authenticate still means auth is needed
		if resp.StatusCode == http.StatusUnauthorized {
			authRequired := true
			si.ConnectionRequestAuthRequired = &authRequired
		}
	}

	// CWMP version detection from response body namespace
	if version := detectCWMPVersion(bodySnip); version != "" {
		si.CwmpVersion = &version
	}

	// Vulnerability signatures
	var vulnSigs []commonProtocol.Tr069VulnSignature
	if si.HttpServer != nil {
		srv := *si.HttpServer
		if rompagerVersion := parseRomPagerVersion(srv); rompagerVersion != "" {
			if isVulnerableRomPager(rompagerVersion) {
				vulnSigs = append(vulnSigs, commonProtocol.Tr069VulnSignatureMisfortuneCookieCve20149222)
			}
		}
		if isMiraiDTClass(srv) {
			vulnSigs = append(vulnSigs, commonProtocol.Tr069VulnSignatureMiraiDtClass)
		}
	}
	if len(vulnSigs) > 0 {
		si.KnownVulnSignatures = vulnSigs
	}

	log.Info("CWMP probe success",
		svc1log.SafeParam("url", url),
		svc1log.SafeParam("status", resp.StatusCode))

	// Build raw response summary (first line of body + headers)
	rawSummary := buildRawSummary(resp, bodySnip)

	// Return nil serverInfo when no CWMP-indicative field was populated.
	// An empty struct would make a generic HTTP listener on port 7547 appear
	// as a fingerprinted TR-069 endpoint with all details unset.
	if si.HttpServer == nil && si.CwmpVersion == nil &&
		si.ConnectionRequestAuthRequired == nil && len(si.KnownVulnSignatures) == 0 {
		return nil, rawSummary, nil
	}
	return si, rawSummary, nil
}

// buildRawSummary builds a compact raw response string for debugging.
func buildRawSummary(resp *http.Response, bodySnip string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP %d\n", resp.StatusCode))
	for k, vv := range resp.Header {
		for _, v := range vv {
			sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}
	if bodySnip != "" {
		sb.WriteString("\n")
		// Cap body to 512 chars in raw summary
		if len(bodySnip) > 512 {
			bodySnip = bodySnip[:512]
		}
		sb.WriteString(bodySnip)
	}
	return sb.String()
}
