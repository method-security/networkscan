// Package dns implements the `enumerate service --service dns` command.
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
	// Off-zone: a recursive answer for it proves the server resolves for anyone.
	DefaultOpenResolverProbe = "a.root-servers.net."

	defaultPort = 53
	queryBudget = 5 * time.Second
	ednsUDPSize = 4096
)

// LibraryEnumerateDNS implements NetworkApplicationLibrary for DNS.
type LibraryEnumerateDNS struct {
	// Empty means DefaultOpenResolverProbe.
	OpenResolverProbe string
}

// EnumerateTarget probes the DNS service at the given target (host:port).
func (l *LibraryEnumerateDNS) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting DNS enumeration", svc1log.SafeParam("target", target))

	errors := []string{}

	host, port, err := splitTarget(target)
	if err != nil {
		errMsg := err.Error()
		return &enumeratefern.EnumerateServiceDetails{
			EnumerateDnsDetails: &dnsfern.EnumerateDnsDetails{Target: target},
		}, append(errors, errMsg)
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

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

	// A REFUSED answer still carries a usable header and OPT record.
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

	if version := chaosTXT(ctx, addr, "version.bind.", &errors); version != "" {
		serverInfo.DnsVersion = &version
	}

	if serverName := chaosTXT(ctx, addr, "id.server.", &errors); serverName != "" {
		serverInfo.ServerName = &serverName
	}

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
		// RA alone only advertises recursion; a real answer confirms it.
		openResolver := resp.RecursionAvailable && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0
		detail.OpenResolver = &openResolver
		if openResolver {
			log.Info("Confirmed open resolver",
				svc1log.SafeParam("target", addr),
				svc1log.SafeParam("probe", probeName))
		}
	}

	// An authoritative-only server refuses this, leaving both fields unset.
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

// exchange sends msg to addr, dialing through netdial to honor a SOCKS proxy.
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

// chaosTXT returns the first TXT string, or "" if the server declines.
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

// absorbHeader records header facts; call only for the first exchange.
func absorbHeader(serverInfo *commonprotocolfern.DnsServerInfo, resp *dns.Msg) {
	responseCode := dns.RcodeToString[resp.Rcode]
	serverInfo.ResponseCode = &responseCode
	authoritative := resp.Authoritative
	serverInfo.Authoritative = &authoritative
	recursionAvailable := resp.RecursionAvailable
	serverInfo.RecursionAvailable = &recursionAvailable
}

// hasDNSSECRecords reports whether the response carries signing material.
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

// extractNSID returns the NSID payload as text; miekg hex-encodes it on unpack.
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

// splitTarget parses host:port, defaulting to 53 only when no port is given.
func splitTarget(target string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return target, defaultPort, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q in target %q", portStr, target)
	}
	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("port %d out of range in target %q", port, target)
	}
	return host, port, nil
}
