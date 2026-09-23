// Package plugins provides DNS service fingerprinting
package plugins

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	"github.com/miekg/dns"
)

type DNSFingerprinter struct{}

func (DNSFingerprinter) Name() string { return "dns" }

func (DNSFingerprinter) DefaultPorts() []int { return []int{53} }

func (DNSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	client := &dns.Client{
		Net:     "udp",
		Timeout: helpers.Timeout(timeout),
	}
	return detectDNS(ctx, client, ip, port, host, common.TransportTypeUdp, nil)
}

type DNSTLSFingerprinter struct{}

func (DNSTLSFingerprinter) Name() string { return "dns-tls" }

func (DNSTLSFingerprinter) DefaultPorts() []int { return []int{853} }

func (DNSTLSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	serverName := host
	if serverName == "" {
		serverName = ip.String()
	}

	client := &dns.Client{
		Net:     "tcp-tls",
		Timeout: helpers.Timeout(timeout),
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
			ServerName:         serverName,
		},
	}
	return detectDNS(ctx, client, ip, port, host, common.TransportTypeTcptls, helpers.BoolPtr(true))
}

func detectDNS(ctx context.Context, client *dns.Client, ip net.IP, port int, host string, transport common.TransportType, tlsEnabled *bool) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	// Create a DNS query for version.bind (CHAOS TXT record)
	// This is commonly used to fingerprint DNS servers
	msg := new(dns.Msg)
	msg.SetQuestion("version.bind.", dns.TypeTXT)
	msg.Question[0].Qclass = dns.ClassCHAOS

	// Send the query
	resp, _, err := client.ExchangeContext(ctx, msg, addr)
	if err != nil {
		// Try a standard query as fallback
		msg = new(dns.Msg)
		msg.SetQuestion(".", dns.TypeNS)
		resp, _, err = client.ExchangeContext(ctx, msg, addr)
		if err != nil {
			return nil, err
		}
	}

	var responseCode *string
	var authoritative *bool
	var recursionAvailable *bool
	var dnsVersion *string
	var edns0Support *bool
	var udpBufferSize *string

	// Extract version information if available
	if resp != nil {
		rcode := dns.RcodeToString[resp.Rcode]
		responseCode = &rcode
		authoritative = &resp.Authoritative
		recursionAvailable = &resp.RecursionAvailable

		// Try to extract version from CHAOS TXT response
		for _, ans := range resp.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				if len(txt.Txt) > 0 {
					version := txt.Txt[0]
					dnsVersion = &version
				}
			}
		}

		// Check for EDNS0 support
		if opt := resp.IsEdns0(); opt != nil {
			edns0True := true
			edns0Support = &edns0True
			bufSize := fmt.Sprintf("%d", opt.UDPSize())
			udpBufferSize = &bufSize
		}
	}

	metadata := &protocol.DnsServerInfo{
		ResponseCode:       responseCode,
		Authoritative:      authoritative,
		RecursionAvailable: recursionAvailable,
		DnsVersion:         dnsVersion,
		Edns0Support:       edns0Support,
		UdpBufferSize:      udpBufferSize,
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       tlsEnabled,
		Transport: transport,
		Protocol:  common.ProtocolTypeDns,
		Version:   dnsVersion,
		Metadata:  &discoverfern.ServiceMetadata{Dns: metadata},
	}

	return result, nil
}
