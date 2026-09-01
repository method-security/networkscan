package plugins

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/miekg/dns"
)

func TestDNSTLSFingerprinterDetect(t *testing.T) {
	ip, port := serveDNSTLS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	details, err := DNSTLSFingerprinter{}.Detect(ctx, ip, port, "localhost", 2)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if details == nil {
		t.Fatal("Detect returned nil details")
	}
	if details.Protocol != common.ProtocolTypeDns {
		t.Errorf("protocol = %s, want %s", details.Protocol, common.ProtocolTypeDns)
	}
	if details.Transport != common.TransportTypeTcptls {
		t.Errorf("transport = %s, want %s", details.Transport, common.TransportTypeTcptls)
	}
	if details.Tls == nil || !*details.Tls {
		t.Errorf("tls = %v, want true", details.Tls)
	}
	if details.Metadata == nil || details.Metadata.Dns == nil || details.Metadata.Dns.DnsVersion == nil {
		t.Fatal("missing DNS metadata")
	}
	if got := *details.Metadata.Dns.DnsVersion; got != "dot-test" {
		t.Errorf("dns version = %q, want %q", got, "dot-test")
	}
}

func serveDNSTLS(t *testing.T) (net.IP, int) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{testTLSCertificate(t)},
	})
	started := make(chan struct{})
	server := &dns.Server{
		Listener:          tlsListener,
		Handler:           dns.HandlerFunc(handleDNSQuery),
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      2 * time.Second,
		NotifyStartedFunc: func() { close(started) },
	}
	go func() {
		_ = server.ActivateAndServe()
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("DNS-over-TLS server did not start")
	}
	t.Cleanup(func() {
		_ = server.Shutdown()
	})

	addr := listener.Addr().(*net.TCPAddr)
	return addr.IP, addr.Port
}

func handleDNSQuery(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	if len(req.Question) > 0 && req.Question[0].Name == "version.bind." && req.Question[0].Qclass == dns.ClassCHAOS {
		resp.Answer = []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{
				Name:   "version.bind.",
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassCHAOS,
			},
			Txt: []string{"dot-test"},
		}}
	}
	_ = w.WriteMsg(resp)
}

func testTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certificateDER},
		PrivateKey:  privateKey,
	}
}
