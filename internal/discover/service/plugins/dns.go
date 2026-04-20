// Package plugins provides DNS service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/miekg/dns"
)

type DNSFingerprinter struct{}

func (DNSFingerprinter) Name() string { return "dns" }

func (DNSFingerprinter) DefaultPorts() []int { return []int{53} }

func (DNSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	// Create DNS client with timeout
	client := &dns.Client{
		Net:     "udp",
		Timeout: time.Duration(timeout) * time.Second,
	}

	// Create a DNS query for version.bind (CHAOS TXT record)
	// This is commonly used to fingerprint DNS servers
	msg := new(dns.Msg)
	msg.SetQuestion("version.bind.", dns.TypeTXT)
	msg.Question[0].Qclass = dns.ClassCHAOS

	// Send the query
	resp, _, err := client.Exchange(msg, addr)
	if err != nil {
		// Try a standard query as fallback
		msg = new(dns.Msg)
		msg.SetQuestion(".", dns.TypeNS)
		resp, _, err = client.Exchange(msg, addr)
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
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeDns,
		Version:   dnsVersion,
		Metadata:  &discoverfern.ServiceMetadata{Dns: metadata},
	}

	return result, nil
}
