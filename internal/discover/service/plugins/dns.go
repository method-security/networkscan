// Package plugins provides DNS service fingerprinting
package plugins

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/miekg/dns"
)

type DNSFingerprinter struct{}

func (DNSFingerprinter) Name() string { return "dns" }

func (DNSFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)

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

	// DNS service detected
	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeDns,
		Metadata:  make(map[string]string),
	}

	// Extract version information if available
	if resp != nil {
		result.Metadata["response_code"] = dns.RcodeToString[resp.Rcode]
		result.Metadata["authoritative"] = fmt.Sprintf("%t", resp.Authoritative)
		result.Metadata["recursion_available"] = fmt.Sprintf("%t", resp.RecursionAvailable)

		// Try to extract version from CHAOS TXT response
		for _, ans := range resp.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				if len(txt.Txt) > 0 {
					version := txt.Txt[0]
					result.Version = &version
					result.Metadata["dns_version"] = version
				}
			}
		}

		// Check for EDNS0 support
		if opt := resp.IsEdns0(); opt != nil {
			result.Metadata["edns0_support"] = "true"
			result.Metadata["udp_buffer_size"] = fmt.Sprintf("%d", opt.UDPSize())
		}
	}

	return result, nil
}
