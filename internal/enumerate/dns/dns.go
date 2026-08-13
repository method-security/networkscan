// Package dns implements the `enumerate service --service dns` command.
//
// The discover-stage plugin (internal/discover/service/plugins/dns.go)
// sends a single version.bind CHAOS TXT query. That is enough to know a
// DNS server is listening; it is not enough to characterize what the
// server will do for an unauthenticated client. This stage adds:
//
//   - Open-resolver confirmation. The RA flag only advertises recursion;
//     the confirmation is a recursive answer for a name the server is not
//     authoritative for.
//   - DNSSEC posture, via a DO-bit DNSKEY query. Only meaningful against a
//     recursive server — an authoritative-only server refuses the probe and
//     the fields stay unset rather than being reported as false.
//   - NSID (RFC 5001) and id.server, which name the specific instance
//     behind an anycast address.
//   - TCP/53 reachability, the precondition for AXFR, so the enumerate
//     report says whether a zone transfer is reachable at all.
package dns

import (
	// Standard
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	// Generated
	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	dnsfern "github.com/Method-Security/networkscan/generated/go/enumerate/dns"

	// Internal
	"github.com/Method-Security/networkscan/internal/netdial"
	// External
	"github.com/miekg/dns"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

const (
	// DefaultOpenResolverProbe is a name no target DNS server should be
	// authoritative for, so a recursive answer for it proves the server
	// resolves on behalf of arbitrary clients. Stable, and unmistakable for
	// traffic against a customer's own zones.
	DefaultOpenResolverProbe = "a.root-servers.net."

	// defaultPort is used when a target carries no port.
	defaultPort = 53

	// queryBudget caps a single DNS exchange. Six probes run in sequence, so
	// the context deadline from --timeout is the real ceiling; this keeps one
	// unresponsive probe from consuming it all.
	queryBudget = 5 * time.Second

	// ednsUDPSize advertises a 4096-byte receive buffer, which prompts the
	// server to report its own in the OPT record it sends back.
	ednsUDPSize = 4096
)

// LibraryEnumerateDNS implements NetworkApplicationLibrary for DNS.
type LibraryEnumerateDNS struct {
	// OpenResolverProbe overrides the off-zone name used to confirm
	// recursion. Empty means DefaultOpenResolverProbe.
	OpenResolverProbe string
}

// EnumerateTarget runs the probe sequence against a single host:port and
// returns the enumerate-details union variant. Probes are independent: a
// failure appends to errors and leaves its fields unset rather than
// abandoning the remaining probes, so a partially responsive server still
// produces a usable characterization.
func (l *LibraryEnumerateDNS) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting DNS enumeration", svc1log.SafeParam("target", target))

	host, port := splitTarget(target)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	errors := []string{}

	probeName := l.OpenResolverProbe
	if probeName == "" {
		probeName = DefaultOpenResolverProbe
	}
	probeName = dns.Fqdn(probeName)

	serverInfo := &commonprotocolfern.DnsServerInfo{}
	detail := &dnsfern.EnumerateDnsDetails{
		Target:            host,
		Port:              port,
		ServerInfo:        serverInfo,
		OpenResolverProbe: &probeName,
	}

	// Probe 1: root NS with EDNS0 + NSID. Populates the response header
	// fields plus EDNS0 support, the server's advertised UDP buffer, and the
	// instance identifier. An authoritative-only server answers REFUSED,
	// which still carries a usable header and OPT record.
	rootQuery := new(dns.Msg)
	rootQuery.SetQuestion(".", dns.TypeNS)
	rootQuery.SetEdns0(ednsUDPSize, false)
	if opt := rootQuery.IsEdns0(); opt != nil {
		opt.Option = append(opt.Option, new(dns.EDNS0_NSID))
	}
	if resp, err := exchange(ctx, "udp", addr, rootQuery); err != nil {
		errors = append(errors, fmt.Sprintf("root NS probe failed for %s: %v", addr, err))
	} else {
		absorbHeader(serverInfo, resp)
		if opt := resp.IsEdns0(); opt != nil {
			edns0 := true
			serverInfo.Edns0Support = &edns0
			bufferSize := strconv.Itoa(int(opt.UDPSize()))
			serverInfo.UdpBufferSize = &bufferSize
			if nsid := extractNSID(opt); nsid != "" {
				detail.Nsid = &nsid
			}
		} else {
			edns0 := false
			serverInfo.Edns0Support = &edns0
		}
	}

	// Probe 2: version.bind. The same query the discover plugin sends; re-run
	// so this report stands on its own.
	if version := chaosTXT(ctx, addr, "version.bind.", &errors); version != "" {
		serverInfo.DnsVersion = &version
	}

	// Probe 3: id.server. Names the responding instance on implementations
	// that decline NSID.
	if serverName := chaosTXT(ctx, addr, "id.server.", &errors); serverName != "" {
		serverInfo.ServerName = &serverName
	}

	// Probe 4: open-resolver confirmation.
	recursionQuery := new(dns.Msg)
	recursionQuery.SetQuestion(probeName, dns.TypeA)
	recursionQuery.RecursionDesired = true
	if resp, err := exchange(ctx, "udp", addr, recursionQuery); err != nil {
		errors = append(errors, fmt.Sprintf("open resolver probe failed for %s: %v", addr, err))
	} else {
		if serverInfo.RecursionAvailable == nil {
			recursionAvailable := resp.RecursionAvailable
			serverInfo.RecursionAvailable = &recursionAvailable
		}
		// Recursion is confirmed only by a real answer: RA plus NOERROR plus
		// at least one record for a name this server does not own.
		openResolver := resp.RecursionAvailable && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0
		detail.OpenResolver = &openResolver
		if openResolver {
			log.Info("Confirmed open resolver",
				svc1log.SafeParam("target", addr),
				svc1log.SafeParam("probe", probeName))
		}
	}

	// Probe 5: DNSSEC. A DO-bit DNSKEY query for the root is answerable by
	// any validating resolver. An authoritative-only server refuses it, so
	// both fields stay unset — "not determined", not "not enabled".
	dnssecQuery := new(dns.Msg)
	dnssecQuery.SetQuestion(".", dns.TypeDNSKEY)
	dnssecQuery.SetEdns0(ednsUDPSize, true)
	dnssecQuery.RecursionDesired = true
	if resp, err := exchange(ctx, "udp", addr, dnssecQuery); err != nil {
		errors = append(errors, fmt.Sprintf("DNSSEC probe failed for %s: %v", addr, err))
	} else if resp.Rcode == dns.RcodeSuccess {
		dnssecEnabled := hasDNSSECRecords(resp)
		serverInfo.DnssecEnabled = &dnssecEnabled
		authenticatedData := resp.AuthenticatedData
		detail.AuthenticatedData = &authenticatedData
	}

	// Probe 6: TCP/53. AXFR needs TCP, so the enumerate report records
	// whether Pentest can reach it before it tries.
	tcpQuery := new(dns.Msg)
	tcpQuery.SetQuestion(".", dns.TypeNS)
	if _, err := exchange(ctx, "tcp", addr, tcpQuery); err != nil {
		tcpAvailable := false
		detail.TcpAvailable = &tcpAvailable
		errors = append(errors, fmt.Sprintf("TCP/53 probe failed for %s: %v", addr, err))
	} else {
		tcpAvailable := true
		detail.TcpAvailable = &tcpAvailable
	}

	return &enumeratefern.EnumerateServiceDetails{EnumerateDnsDetails: detail}, errors
}

// exchange sends msg to addr over network and returns the response. Dials
// through netdial so a SOCKS proxy carried on the context is honored for the
// TCP probes.
func exchange(ctx context.Context, network, addr string, msg *dns.Msg) (*dns.Msg, error) {
	budget := queryBudget
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < budget {
			budget = remaining
		}
	}
	if budget <= 0 {
		return nil, context.DeadlineExceeded
	}

	conn, err := netdial.DialContext(ctx, network, addr, netdial.WithTimeout(budget))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(budget))

	client := &dns.Client{Net: network, Timeout: budget}
	resp, _, err := client.ExchangeWithConnContext(ctx, msg, &dns.Conn{Conn: conn})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("empty response from %s", addr)
	}
	return resp, nil
}

// chaosTXT sends a CHAOS-class TXT query and returns the first string of the
// first TXT record, or "" when the server declines to answer. CHAOS queries
// are sent without EDNS0 — some implementations drop the combination.
func chaosTXT(ctx context.Context, addr, name string, errors *[]string) string {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeTXT)
	msg.Question[0].Qclass = dns.ClassCHAOS

	resp, err := exchange(ctx, "udp", addr, msg)
	if err != nil {
		*errors = append(*errors, fmt.Sprintf("%s probe failed for %s: %v", strings.TrimSuffix(name, "."), addr, err))
		return ""
	}
	for _, answer := range resp.Answer {
		if txt, ok := answer.(*dns.TXT); ok && len(txt.Txt) > 0 {
			return txt.Txt[0]
		}
	}
	return ""
}

// absorbHeader records the response-header facts that every probe reveals.
// Called for the first successful exchange only; later probes set different
// flags (RD, DO) and their headers would describe a different question.
func absorbHeader(serverInfo *commonprotocolfern.DnsServerInfo, resp *dns.Msg) {
	responseCode := dns.RcodeToString[resp.Rcode]
	serverInfo.ResponseCode = &responseCode
	authoritative := resp.Authoritative
	serverInfo.Authoritative = &authoritative
	recursionAvailable := resp.RecursionAvailable
	serverInfo.RecursionAvailable = &recursionAvailable
}

// hasDNSSECRecords reports whether the response carries signing material,
// which is what distinguishes a DNSSEC-aware server from one that merely
// echoed the DO bit.
func hasDNSSECRecords(resp *dns.Msg) bool {
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, rr := range section {
			switch rr.(type) {
			case *dns.RRSIG, *dns.DNSKEY, *dns.NSEC, *dns.NSEC3, *dns.DS:
				return true
			}
		}
	}
	return false
}

// extractNSID returns the NSID payload as text. miekg hex-encodes the option
// on unpack; most implementations put a readable host label in it, so decode
// when the result is valid UTF-8 and fall back to the hex otherwise.
func extractNSID(opt *dns.OPT) string {
	for _, option := range opt.Option {
		nsid, ok := option.(*dns.EDNS0_NSID)
		if !ok || nsid.Nsid == "" {
			continue
		}
		decoded, err := hex.DecodeString(nsid.Nsid)
		if err != nil || !utf8.Valid(decoded) {
			return nsid.Nsid
		}
		return string(decoded)
	}
	return ""
}

// splitTarget parses a host:port target, defaulting to port 53 when the
// target carries only a host. Ontology always sends host:port; operators
// invoking the CLI directly frequently do not.
func splitTarget(target string) (string, int) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return target, defaultPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return host, defaultPort
	}
	return host, port
}
