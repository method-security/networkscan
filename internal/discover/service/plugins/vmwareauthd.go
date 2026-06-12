// Package plugins provides VMware Authentication Daemon (authd) service fingerprinting.
// It performs the full ESXi authd protocol exchange: banner parse → CAPS → VERSION →
// optional SSL upgrade → TLS cert capture.
package plugins

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

// VMwareAuthdFingerprinter fingerprints VMware ESXi authentication daemon (port 902).
type VMwareAuthdFingerprinter struct{}

func (VMwareAuthdFingerprinter) Name() string { return "vmware-authd" }

func (VMwareAuthdFingerprinter) DefaultPorts() []int { return []int{902} }

func (VMwareAuthdFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	dur := helpers.Timeout(timeout)

	conn, err := helpers.DialDuration(ctx, "tcp", addr, dur)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	_ = helpers.SetReadDeadlineDuration(conn, dur)
	reader := bufio.NewReader(conn)

	// Read and drain the full 220 greeting — authd may emit SMTP-style
	// "220-" continuation lines before the final "220 " terminator.
	// Without draining all of them the bufio buffer would contain leftover
	// greeting lines that readMultiline200 would mis-parse as the CAPS reply,
	// marking the wire dirty and skipping VERSION + SSL/TLS.
	var bannerLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if !strings.HasPrefix(line, "220") {
			return nil, fmt.Errorf("not VMware authd: %s", line)
		}
		bannerLines = append(bannerLines, line)
		if len(line) < 4 || line[3] == ' ' {
			break // terminal line
		}
		// line[3] == '-': continuation line, keep reading
	}
	banner := bannerLines[len(bannerLines)-1]
	if !strings.HasPrefix(banner, "220 VMware Authentication Daemon") {
		return nil, fmt.Errorf("not VMware authd: %s", banner)
	}

	// Build a combined text of ALL banner lines for parsing — SSL flags or
	// other fields may appear on 220- continuation lines, not only on the
	// terminal "220 " line. info.Banner stores the terminal line (clean display);
	// parseAuthdBanner receives the full multi-line text so no flags are missed.
	fullBanner := strings.Join(bannerLines, " ")

	info := &protocol.VmwareAuthdServerInfo{}
	bannerCopy := banner
	info.Banner = &bannerCopy
	parseAuthdBanner(fullBanner, info)

	// CAPS exchange — multi-line "200-…" / final "200 …" (SMTP final-space convention).
	// wireClean tracks whether subsequent reads on this conn are safe: true when
	// we never sent CAPS (nothing to consume), OR after any CAPS exchange that
	// left the bufio buffer empty (terminal 200 line seen, OR a single non-200
	// reply fully consumed). False only when there may be leftover bytes on the
	// wire (read error, or the 4096-line drain cap was reached without a terminal).
	wireClean := true
	_ = helpers.SetWriteDeadlineDuration(conn, dur)
	if _, err := conn.Write([]byte("CAPS\r\n")); err == nil {
		_ = helpers.SetReadDeadlineDuration(conn, dur)
		caps, capsWireClean := readMultiline200(reader)
		if len(caps) > 0 {
			info.Capabilities = caps
		}
		// capsWireClean is false only when unread bytes may remain on the
		// wire (read error, or the drain cap was reached without a terminal).
		// A single non-200 reply (e.g. 5xx) is fully consumed and returns
		// capsWireClean=true, so VERSION + SSL still proceed in that case.
		wireClean = capsWireClean
	}

	// VERSION exchange — single line response. Skipped if CAPS started but
	// didn't terminate cleanly: the next ReadString would pick up a stale
	// "200-…" continuation and clobber versionResponse / build / esxi fields.
	if wireClean {
		_ = helpers.SetWriteDeadlineDuration(conn, dur)
		if _, err := conn.Write([]byte("VERSION\r\n")); err == nil {
			_ = helpers.SetReadDeadlineDuration(conn, dur)
			if v, err := reader.ReadString('\n'); err == nil {
				v = strings.TrimRight(v, "\r\n")
				info.VersionResponse = &v
				// Some builds echo ESXi version / build in VERSION reply too.
				parseVersionReply(v, info)
			}
		}
	}

	tlsUsed := false
	transport := common.TransportTypeTcp

	// SSL upgrade — only if banner advertised SSL (Required or Recommended) AND
	// the wire is still clean. With a dirty wire the prefixedConn hand-off
	// below would feed leftover plaintext CAPS bytes into the TLS handshake
	// and corrupt it.
	sslAdvertised := (info.SslRequired != nil && *info.SslRequired) ||
		(info.SslRecommended != nil && *info.SslRecommended)
	if sslAdvertised && wireClean {
		_ = helpers.SetWriteDeadlineDuration(conn, dur)
		if _, err := conn.Write([]byte("SSL\r\n")); err == nil {
			// Read SSL ack — single 200-prefixed line is typical; tolerate empty/non-200.
			_ = helpers.SetReadDeadlineDuration(conn, dur)
			ack, _ := reader.ReadString('\n')
			ack = strings.TrimSpace(ack)
			if strings.HasPrefix(ack, "200") || ack == "" {
				// Drain any bytes the bufio.Reader has buffered beyond the SSL
				// ack line — if the server pipelined the ack and the first TLS
				// record in one TCP segment, those TLS bytes are sitting in the
				// bufio buffer and would be invisible to tls.Client(conn).
				// Wrap conn so the TLS layer sees the buffered prefix first,
				// then the underlying socket. Without this the handshake will
				// fail spuriously on TLS-capable hosts.
				tlsConn := conn
				if buffered := reader.Buffered(); buffered > 0 {
					prefix := make([]byte, buffered)
					if _, peekErr := io.ReadFull(reader, prefix); peekErr == nil {
						tlsConn = &prefixedConn{Conn: conn, prefix: bytes.NewReader(prefix)}
					}
				}
				// InsecureSkipVerify is intentional: this is a fingerprinting probe.
				// We connect specifically to capture whatever certificate the host
				// presents — typically a self-signed ESXi vmware-vpxa cert — so a
				// trust-chain check would defeat the purpose. The captured chain is
				// returned for downstream analysis; we never use this TLS session
				// for authenticated traffic.
				tc := tls.Client(tlsConn, makeAuthdTLSConfig(host))
				_ = helpers.SetDeadlineDuration(tc, dur)
				if hsErr := tc.Handshake(); hsErr == nil {
					tlsUsed = true
					transport = common.TransportTypeTcptls
					trueBool := true
					info.SslSupported = &trueBool
					info.TlsUpgraded = &trueBool
					certs := extractAuthdCerts(tc.ConnectionState().PeerCertificates)
					if len(certs) > 0 {
						info.TlsCertificates = certs
					}
				} else {
					falseBool := false
					info.SslSupported = &falseBool
					info.TlsUpgraded = &falseBool
				}
			} else {
				falseBool := false
				info.SslSupported = &falseBool
				info.TlsUpgraded = &falseBool
			}
		}
	}

	// QUIT — best-effort, ignore errors (cleartext side only; TLS conn may have closed already)
	if !tlsUsed {
		_ = helpers.SetWriteDeadlineDuration(conn, dur)
		_, _ = conn.Write([]byte("QUIT\r\n"))
	}

	// Display version: prefer "VMware authd <ver>" when the daemon version
	// parsed cleanly; otherwise fall back to the short label rather than the
	// full 220 banner string so downstream display fields stay short.
	version := "VMware authd"
	if info.DaemonVersion != nil && *info.DaemonVersion != "" {
		version = "VMware authd " + *info.DaemonVersion
	}

	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       tlsUsed,
		Transport: transport,
		Protocol:  common.ProtocolTypeVmwareauthd,
		Version:   &version,
		Metadata:  &discoverfern.ServiceMetadata{Vmwareauthd: info},
	}, nil
}

// readMultiline200 reads SMTP-style multi-line "200-…" replies, stopping at
// "200 …". Returns the payload lines and a wireClean flag.
//
// wireClean is true when the bufio buffer has no unconsumed bytes that would
// corrupt a subsequent read:
//   - The terminal "200 " line was seen (happy path).
//   - The server replied with a single non-200 line (e.g. 5xx error) that was
//     fully consumed — the wire is clean even though no capabilities were
//     exchanged.
//
// wireClean is false when bytes may still remain:
//   - A read error occurred (connection reset, timeout, partial data).
//   - The drainCap was reached without a terminal (leftover continuation lines).
//   - A non-200 line appeared mid-stream after 200- continuations (malformed).
//
// Storage is bounded at storeCap entries; the wire is drained up to drainCap
// lines so subsequent reads aren't polluted by leftover continuation lines.
func readMultiline200(r *bufio.Reader) ([]string, bool) {
	const storeCap = 64
	const drainCap = 4096
	var out []string
	for i := 0; i < drainCap; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			return out, false // read error: wire state unknown
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 4 || !strings.HasPrefix(line, "200") {
			// Non-200 line fully consumed. Wire is clean only when no
			// continuation lines were seen yet (first/only reply line, e.g.
			// a 5xx error). After some 200- continuations a mid-stream
			// non-200 is malformed; treat wire as dirty.
			return out, len(out) == 0
		}
		if len(out) < storeCap {
			payload := strings.TrimSpace(line[4:])
			if payload != "" {
				out = append(out, payload)
			}
		}
		if line[3] == ' ' {
			return out, true // terminal line: wire clean
		}
	}
	return out, false // drainCap exhausted: leftover lines remain
}

// parseAuthdBanner extracts daemon version, SSL requirement, sub-protocols,
// capability flags, and any ESXi version / build / mgmt-agent text from the
// 220 greeting.
func parseAuthdBanner(banner string, info *protocol.VmwareAuthdServerInfo) {
	// Daemon Version (e.g. "Version 1.10:" or "Version 1.10,")
	if m := regexp.MustCompile(`Version\s+([\w.]+)`).FindStringSubmatch(banner); len(m) == 2 {
		v := m[1]
		info.DaemonVersion = &v
	}
	upper := strings.ToUpper(banner)
	// Use word-boundary matching to distinguish the standalone "SSL REQUIRED" /
	// "SSL RECOMMENDED" tokens from "NFCSSL RECOMMENDED" (NFC-over-SSL, a separate
	// transport). "NFCSSL RECOMMENDED" contains "SSL RECOMMENDED" as a substring
	// and would otherwise incorrectly trigger the SSL upgrade probe.
	sslRequired := regexp.MustCompile(`\bSSL REQUIRED\b`).MatchString(upper)
	sslRecommended := regexp.MustCompile(`\bSSL RECOMMENDED\b`).MatchString(upper)
	if sslRequired {
		t := true
		f := false
		info.SslRequired = &t
		info.SslRecommended = &f
	} else if sslRecommended {
		t := true
		f := false
		info.SslRequired = &f
		info.SslRecommended = &t
	} else {
		f := false
		info.SslRequired = &f
		info.SslRecommended = &f
	}
	t := true
	f := false
	if strings.Contains(upper, "NFCSSL SUPPORTED") || strings.Contains(upper, "NFCSSL RECOMMENDED") {
		info.NfcsslSupported = &t
	} else {
		info.NfcsslSupported = &f
	}
	if strings.Contains(upper, "VMXARGS SUPPORTED") {
		info.VmxargsSupported = &t
	} else {
		info.VmxargsSupported = &f
	}
	if m := regexp.MustCompile(`(?i)ServerDaemonProtocol:\s*([A-Za-z0-9_]+)`).FindStringSubmatch(banner); len(m) == 2 {
		s := m[1]
		info.ServerDaemonProtocol = &s
	}
	if m := regexp.MustCompile(`(?i)MKSDisplayProtocol:\s*([A-Za-z0-9_]+)`).FindStringSubmatch(banner); len(m) == 2 {
		s := m[1]
		info.MksDisplayProtocol = &s
	}
	// Optional Build:NNNNNN / ESXi:7.0.x suffix some builds emit.
	if m := regexp.MustCompile(`(?i)Build[:\s]+(\d+)`).FindStringSubmatch(banner); len(m) == 2 {
		s := m[1]
		info.BuildNumber = &s
	}
	if m := regexp.MustCompile(`(?i)ESXi[:\s]+([\w.]+)`).FindStringSubmatch(banner); len(m) == 2 {
		s := m[1]
		info.EsxiVersion = &s
	}
	// Mgmt-agent style banner — heuristic: trailing portion after "Banner:" keyword.
	if m := regexp.MustCompile(`(?i)Banner:\s*([^,;]+)`).FindStringSubmatch(banner); len(m) == 2 {
		s := strings.TrimSpace(m[1])
		info.ManagementAgentBanner = &s
	}
}

func parseVersionReply(line string, info *protocol.VmwareAuthdServerInfo) {
	if info.BuildNumber == nil {
		if m := regexp.MustCompile(`(?i)Build[:\s]+(\d+)`).FindStringSubmatch(line); len(m) == 2 {
			s := m[1]
			info.BuildNumber = &s
		}
	}
	if info.EsxiVersion == nil {
		if m := regexp.MustCompile(`(?i)ESXi[:\s]+([\w.]+)`).FindStringSubmatch(line); len(m) == 2 {
			s := m[1]
			info.EsxiVersion = &s
		}
	}
}

// prefixedConn is a net.Conn that yields the bytes in `prefix` before reading
// from the underlying Conn. We need this so tls.Client can see any bytes that
// were buffered inside a bufio.Reader on the cleartext side before the SSL
// upgrade — without it, pipelined "200 ack + first TLS record" payloads stall
// the handshake.
type prefixedConn struct {
	net.Conn
	prefix *bytes.Reader
}

func (p *prefixedConn) Read(b []byte) (int, error) {
	if p.prefix != nil && p.prefix.Len() > 0 {
		n, err := p.prefix.Read(b)
		if err == io.EOF {
			err = nil
		}
		return n, err
	}
	return p.Conn.Read(b)
}

// makeAuthdTLSConfig returns a TLS client config that intentionally skips
// certificate verification. This is a probe-style dial against ESXi hosts
// that almost universally present self-signed vpxa certificates; the captured
// chain is reported back to the caller for analysis and is never used for
// authenticated traffic. The function exists so the static analyzers can
// see the rationale localized to one place rather than chasing literal
// tls.Config{InsecureSkipVerify: true} sites.
func makeAuthdTLSConfig(host string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // see function comment — fingerprinting, not verifying
		ServerName:         host,
	}
}

// extractAuthdCerts converts an x509 chain into the slim Fern shape defined
// in protocol.VmwareAuthdCertificate.
func extractAuthdCerts(chain []*x509.Certificate) []*protocol.VmwareAuthdCertificate {
	out := make([]*protocol.VmwareAuthdCertificate, 0, len(chain))
	for _, c := range chain {
		cert := &protocol.VmwareAuthdCertificate{}
		if c.Subject.CommonName != "" {
			s := c.Subject.CommonName
			cert.SubjectCommonName = &s
		}
		if c.Issuer.CommonName != "" {
			s := c.Issuer.CommonName
			cert.IssuerCommonName = &s
		}
		if len(c.DNSNames) > 0 {
			cert.SubjectAlternativeNames = c.DNSNames
		}
		if c.SerialNumber != nil {
			s := c.SerialNumber.String()
			cert.SerialNumber = &s
		}
		nb := c.NotBefore
		cert.NotBefore = &nb
		na := c.NotAfter
		cert.NotAfter = &na
		sum := sha256.Sum256(c.Raw)
		fp := hex.EncodeToString(sum[:])
		cert.Sha256Fingerprint = &fp
		sigAlg := c.SignatureAlgorithm.String()
		cert.SignatureAlgorithm = &sigAlg
		pkAlg := c.PublicKeyAlgorithm.String()
		cert.PublicKeyAlgorithm = &pkAlg
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
		pemStr := string(pemBytes)
		cert.PemEncoded = &pemStr
		out = append(out, cert)
	}
	return out
}
