package service

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

func TestTCPBatchDiscoversNativeHTTPAndVNCOnNonDefaultPorts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "networkscan-test")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				_, _ = conn.Write([]byte("RFB 003.008\n"))
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// Leave room for the HTTP analyzer's first-use initialization under -race.
	report, err := RunTCPServiceFingerprint(ctx, discoverfern.DiscoverServiceConfig{Targets: []string{server.Listener.Addr().String(), listener.Addr().String()}, Timeout: 3, Threads: 2, PluginThreads: 16})
	if err != nil || report.Result == nil || len(report.Result.Services) != 2 {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	if report.Result.Services[0].Protocol != "HTTP" || report.Result.Services[1].Protocol != "VNC" {
		t.Fatalf("wrong protocols: %s, %s", report.Result.Services[0].Protocol, report.Result.Services[1].Protocol)
	}
	if len(report.Errors) > 0 {
		t.Fatalf("errors=%v", report.Errors)
	}
	_ = listener.Close()
	<-stopped
}

type blockingFingerprinter struct {
	started chan<- string
	release <-chan struct{}
}

func (b *blockingFingerprinter) Name() string {
	return "blocking"
}

func (b *blockingFingerprinter) DefaultPorts() []int {
	return nil
}

func (b *blockingFingerprinter) Detect(ctx context.Context, ip net.IP, port int, _ string, _ int) (*discoverfern.ServiceDetails, error) {
	select {
	case b.started <- fmt.Sprintf("%s:%d", ip, port):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	select {
	case <-b.release:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type timeoutFingerprinter struct{}

func (t *timeoutFingerprinter) Name() string {
	return "timeout"
}

func (t *timeoutFingerprinter) DefaultPorts() []int {
	return nil
}

func (t *timeoutFingerprinter) Detect(ctx context.Context, _ net.IP, _ int, _ string, _ int) (*discoverfern.ServiceDetails, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type resultFingerprinter struct{}

func (r *resultFingerprinter) Name() string {
	return "result"
}

func (r *resultFingerprinter) DefaultPorts() []int {
	return nil
}

func (r *resultFingerprinter) Detect(_ context.Context, _ net.IP, port int, _ string, _ int) (*discoverfern.ServiceDetails, error) {
	return &discoverfern.ServiceDetails{Port: port}, nil
}

type hostResultFingerprinter struct{}

func (h *hostResultFingerprinter) Name() string {
	return "host-result"
}

func (h *hostResultFingerprinter) DefaultPorts() []int {
	return nil
}

func (h *hostResultFingerprinter) Detect(_ context.Context, _ net.IP, port int, host string, _ int) (*discoverfern.ServiceDetails, error) {
	return &discoverfern.ServiceDetails{Host: host, Port: port}, nil
}

type stubbornFingerprinter struct {
	release <-chan struct{}
}

func (s *stubbornFingerprinter) Name() string {
	return "stubborn"
}

func (s *stubbornFingerprinter) DefaultPorts() []int {
	return nil
}

func (s *stubbornFingerprinter) Detect(_ context.Context, _ net.IP, _ int, _ string, _ int) (*discoverfern.ServiceDetails, error) {
	<-s.release
	return nil, nil
}

func TestRunFingerprintersParallelTimeoutIsPerPlugin(t *testing.T) {
	detection := runFingerprintersParallel(
		context.Background(),
		[]Fingerprinter{&timeoutFingerprinter{}, &resultFingerprinter{}},
		net.ParseIP("10.0.0.1"),
		443,
		"10.0.0.1",
		1,
		1,
	)

	if detection == nil || detection.Port != 443 {
		t.Fatalf("detection = %#v, want queued plugin result", detection)
	}
}

func TestRunFingerprintersParallelTimeoutDoesNotBlockOnStubbornPlugin(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	start := time.Now()
	detection := runFingerprintersParallel(
		context.Background(),
		[]Fingerprinter{&stubbornFingerprinter{release: release}, &resultFingerprinter{}},
		net.ParseIP("10.0.0.1"),
		443,
		"10.0.0.1",
		1,
		1,
	)

	if detection == nil || detection.Port != 443 {
		t.Fatalf("detection = %#v, want queued plugin result", detection)
	}
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Fatalf("elapsed = %s, want stubborn plugin timeout to release worker", elapsed)
	}
}

func TestParseServiceTargetsUsesPerIPHostForExpandedTargets(t *testing.T) {
	targets, err := parseServiceTargets("10.0.0.0/30")
	if err != nil {
		t.Fatalf("parseServiceTargets returned error: %v", err)
	}

	if len(targets) != 4 {
		t.Fatalf("target count = %d, want 4", len(targets))
	}
	for _, target := range targets {
		if target.host != target.ip.String() {
			t.Fatalf("target host = %q for ip %q, want per-IP host", target.host, target.ip)
		}
	}
}

func TestParseTCPServiceTargetsSupportsMultiplePorts(t *testing.T) {
	targets, err := parseTCPServiceTargets([]string{"10.0.0.1:22", "10.0.0.4/30:443"})
	if err != nil {
		t.Fatalf("parseTCPServiceTargets returned error: %v", err)
	}

	if len(targets) != 5 {
		t.Fatalf("target count = %d, want 5", len(targets))
	}
	if targets[0].host != "10.0.0.1" || targets[0].port != 22 {
		t.Fatalf("first target = %#v, want 10.0.0.1:22", targets[0])
	}
	for _, target := range targets[1:] {
		if target.port != 443 {
			t.Fatalf("expanded target port = %d, want 443", target.port)
		}
		if target.host != target.ip.String() {
			t.Fatalf("expanded target host = %q for ip %q, want per-IP host", target.host, target.ip)
		}
	}
}

func TestRunUDPServiceDiscoveryThreadsTargetsAndPlugins(t *testing.T) {
	originalFingerprinters := udpFingerprinters
	defer func() { udpFingerprinters = originalFingerprinters }()

	started := make(chan string, 4)
	release := make(chan struct{})
	fingerprinter := &blockingFingerprinter{started: started, release: release}
	udpFingerprinters = map[uint16]Fingerprinter{
		53:  fingerprinter,
		123: fingerprinter,
	}

	udp := true
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = runUDPServiceDiscovery(context.Background(), discoverfern.DiscoverServiceConfig{
			Targets:       []string{"10.0.0.0/30"},
			Timeout:       -1,
			Threads:       2,
			PluginThreads: 2,
			Udp:           &udp,
		})
	}()

	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("received %d of 4 concurrent starts", i)
		}
	}

	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UDP discovery did not complete after releasing probes")
	}
}

func TestRunUDPServiceDiscoverySeparatesTargetAndPluginThreads(t *testing.T) {
	originalFingerprinters := udpFingerprinters
	defer func() { udpFingerprinters = originalFingerprinters }()

	started := make(chan string, 8)
	release := make(chan struct{})
	fingerprinter := &blockingFingerprinter{started: started, release: release}
	udpFingerprinters = map[uint16]Fingerprinter{
		53:  fingerprinter,
		123: fingerprinter,
	}

	udp := true
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = runUDPServiceDiscovery(context.Background(), discoverfern.DiscoverServiceConfig{
			Targets:       []string{"10.0.0.0/30"},
			Timeout:       -1,
			Threads:       2,
			PluginThreads: 1,
			Udp:           &udp,
		})
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("received %d of 2 concurrent starts", i)
		}
	}

	select {
	case start := <-started:
		t.Fatalf("unexpected third probe before release: %s", start)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UDP discovery did not complete after releasing probes")
	}
}

func TestRunUDPServiceDiscoveryCollectsEveryDetection(t *testing.T) {
	originalFingerprinters := udpFingerprinters
	defer func() { udpFingerprinters = originalFingerprinters }()

	udpFingerprinters = make(map[uint16]Fingerprinter, 64)
	for port := uint16(1); port <= 64; port++ {
		udpFingerprinters[port] = &resultFingerprinter{}
	}

	results := runUDPServiceDiscoveryForIP(context.Background(), discoverfern.DiscoverServiceConfig{
		Timeout:       1,
		PluginThreads: 64,
	}, net.ParseIP("10.0.0.1"), "10.0.0.1")

	if len(results) != len(udpFingerprinters) {
		t.Fatalf("result count = %d, want %d", len(results), len(udpFingerprinters))
	}
}

func TestRunUDPServiceDiscoveryForIPPreservesFingerprintHost(t *testing.T) {
	originalFingerprinters := udpFingerprinters
	defer func() { udpFingerprinters = originalFingerprinters }()

	udpFingerprinters = map[uint16]Fingerprinter{
		53: &hostResultFingerprinter{},
	}

	results := runUDPServiceDiscoveryForIP(context.Background(), discoverfern.DiscoverServiceConfig{
		Timeout:       1,
		PluginThreads: 1,
	}, net.ParseIP("10.0.0.1"), "dns.internal")

	if len(results) != 1 || results[0].Host != "dns.internal" {
		t.Fatalf("results = %#v, want preserved UDP fingerprint host", results)
	}
}

func TestRunUDPServiceDiscoveryTimeoutDoesNotBlockOnStubbornPlugin(t *testing.T) {
	originalFingerprinters := udpFingerprinters
	defer func() { udpFingerprinters = originalFingerprinters }()

	release := make(chan struct{})
	defer close(release)
	udpFingerprinters = map[uint16]Fingerprinter{
		53:  &stubbornFingerprinter{release: release},
		123: &resultFingerprinter{},
	}

	start := time.Now()
	results := runUDPServiceDiscoveryForIP(context.Background(), discoverfern.DiscoverServiceConfig{
		Timeout:       1,
		PluginThreads: 1,
	}, net.ParseIP("10.0.0.1"), "10.0.0.1")

	if len(results) != 1 || results[0].Port != 123 {
		t.Fatalf("results = %#v, want UDP result after stubborn plugin timeout", results)
	}
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Fatalf("elapsed = %s, want stubborn UDP plugin timeout to release worker", elapsed)
	}
}

// This inventory preserves plugin order and port mappings from before registration was centralized.
func TestTCPPluginRegistry(t *testing.T) {
	want := []string{
		"*plugins.SSHFingerprinter|ssh|[22 2222]",
		"*plugins.DNSTCPFingerprinter|dns-tcp|[53]",
		"*plugins.DNSTLSFingerprinter|dns-tls|[853]",
		"*plugins.EtcdFingerprinter|etcd|[2379]",
		"*plugins.RedisFingerprinter|redis|[6379 6380 26379]",
		"*plugins.MongoDBFingerprinter|mongodb|[27017]",
		"*plugins.CassandraFingerprinter|cassandra|[9042]",
		"*plugins.BGPFingerprinter|bgp|[179]",
		"*plugins.DCERPCFingerprinter|dcerpc|[135]",
		"*plugins.IPPFingerprinter|ipp|[631]",
		"*plugins.WinRMFingerprinter|winrm|[5985 5986]",
		"*plugins.KerberosFingerprinter|kerberos|[88]",
		"*plugins.SMBFingerprinter|smb|[445 139]",
		"*plugins.FortiGateFingerprinter|fortigate-fgfm|[541]",
		"*plugins.PcworxFingerprinter|pcworx|[1962]",
		"*plugins.OpcuaFingerprinter|opcua|[4840]",
		"*plugins.X11Fingerprinter|x11|[6000 6001 6002 6003 6004 6005 6006 6007 6008 6009 6010 6011 6012 6013 6014 6015 6016 6017 6018 6019 6020 6021 6022 6023 6024 6025 6026 6027 6028 6029 6030 6031 6032 6033 6034 6035 6036 6037 6038 6039 6040 6041 6042 6043 6044 6045 6046 6047 6048 6049 6050 6051 6052 6053 6054 6055 6056 6057 6058 6059 6060 6061 6062 6063]",
		"*plugins.PcomFingerprinter|pcom|[20256]",
		"*plugins.Iec104Fingerprinter|iec104|[2404]",
		"*plugins.GesrtpFingerprinter|gesrtp|[18245 18246]",
		"*plugins.FinsFingerprinter|fins|[9600]",
		"*plugins.AtgFingerprinter|atg|[10001]",
		"*plugins.ArdFingerprinter|ard|[3283 5900]",
		"*plugins.PptpFingerprinter|pptp|[1723]",
		"*plugins.MsmqFingerprinter|msmq|[1801 2103 2105]",
		"*plugins.S7CommFingerprinter|s7comm|[102]",
		"*plugins.MmsFingerprinter|mms|[102]",
		"*plugins.HartFingerprinter|hart|[5094 20004]",
		"*plugins.FoxFingerprinter|fox|[1911 4911]",
		"*plugins.MemcachedFingerprinter|memcached|[11211]",
		"*plugins.UnistreamFingerprinter|unistream|[44818]",
		"*plugins.EthernetIPFingerprinter|ethernetip|[44818]",
		"*plugins.OracleFingerprinter|oracle|[1521 1522 1525]",
		"*plugins.SMTPFingerprinter|smtp|[25 587 2525 8025]",
		"*plugins.JMXFingerprinter|jmx|[1099 7676 8686 9010 9011 9076 9119 9611 9999 7199 7091]",
		"*plugins.JavaRMIFingerprinter|java-rmi|[1099]",
		"*plugins.AJP13Fingerprinter|ajp13|[8009]",
		"*plugins.GrpcFingerprinter|grpc|[]",
		"*plugins.WebLogicT3Fingerprinter|weblogic-t3|[7001 7002]",
		"*plugins.ZooKeeperFingerprinter|zookeeper|[2181]",
		"*plugins.AMQPFingerprinter|amqp|[5672]",
		"*plugins.NATSFingerprinter|nats|[4222]",
		"*plugins.BeanstalkdFingerprinter|beanstalkd|[11300]",
		"*plugins.ErlangEPMDFingerprinter|erlang-epmd|[4369]",
		"*plugins.ADBFingerprinter|adb|[5555]",
		"*plugins.RTMPFingerprinter|rtmp|[1935]",
		"*plugins.SCCPFingerprinter|sccp|[2000]",
		"*plugins.SOCKSFingerprinter|socks|[1080 1081 9050 9150]",
		"*plugins.NNTPFingerprinter|nntp|[119 563]",
		"*plugins.IRCFingerprinter|irc|[6660 6667 6697]",
		"*plugins.XMPPFingerprinter|xmpp|[5222 5269]",
		"*plugins.IdentFingerprinter|ident|[113]",
		"*plugins.GopherFingerprinter|gopher|[70]",
		"*plugins.AFPFingerprinter|afp|[548]",
		"*plugins.GitDaemonFingerprinter|git-daemon|[9418]",
		"*plugins.FingerFingerprinter|finger|[79]",
		"*plugins.WhoisFingerprinter|whois|[43]",
		"*plugins.VMwareAuthdFingerprinter|vmware-authd|[902]",
		"*plugins.PoppassdFingerprinter|poppassd|[106]",
		"*plugins.JetDirectFingerprinter|jetdirect|[9100]",
		"*plugins.LPDFingerprinter|lpd|[515]",
		"*plugins.RloginFingerprinter|rlogin|[513]",
		"*plugins.DubboFingerprinter|dubbo|[20880]",
		"*plugins.TarantoolFingerprinter|tarantool|[3301]",
		"*plugins.DNP3Fingerprinter|dnp3|[20000]",
		"*plugins.MELSECFingerprinter|melsec|[5000 5001 5006 5007 20000]",
		"*plugins.CodesysFingerprinter|codesys|[1200 1210 1211 1217 1740 1741 1742 1743 11740]",
		"*plugins.BeckhoffADSFingerprinter|beckhoff-ads|[48898]",
		"*plugins.SAPRouterFingerprinter|saprouter|[3299]",
		"*plugins.NDMPFingerprinter|ndmp|[10000]",
		"*plugins.HPDataProtectorFingerprinter|hpdataprotector|[5555 5556 12328 16400]",
		"*plugins.NFSFingerprinter|nfs|[2049]",
		"*plugins.WinboxFingerprinter|winbox|[8291]",
		"*neo4j.NEO4JPlugin|neo4j|[7687]",
		"*neo4j.NEO4JTLSPlugin|neo4j|[7687]",
		"*echo.EchoPlugin|echo|[7]",
		"*telnet.TELNETPlugin|telnet|[23]",
		"*ftp.FTPPlugin|ftp|[21]",
		"*snpp.SNPPPlugin|snpp|[444]",
		"*kubernetes.KubernetesPlugin|kubernetes|[6443]",
		"*chromadb.ChromaDBPlugin|chromadb|[8000]",
		"*milvus.MilvusPlugin|milvus|[19530]",
		"*pinecone.PINECONEPlugin|pinecone|[443]",
		"*chromadb.ChromaDBTLSPlugin|chromadb|[8000]",
		"*milvus.MilvusMetricsPlugin|milvus-metrics|[9091]",
		"*smpp.SMPPPlugin|smpp|[2775 2776]",
		"*diameter.DIAMETERPlugin|diameter|[3868]",
		"*smtp.TLSPlugin|smtps|[465]",
		"*rdp.RDPPlugin|rdp|[3389]",
		"*rdp.TLSPlugin|rdp|[3389]",
		"*firebird.FirebirdPlugin|firebird|[3050]",
		"*couchdb.COUCHDBPlugin|couchdb|[5984]",
		"*elasticsearch.ElasticsearchPlugin|elasticsearch|[9200]",
		"*influxdb.InfluxDBPlugin|influxdb|[8086]",
		"*couchdb.COUCHDBTLSPlugin|couchdb|[6984]",
		"*pop3.POP3Plugin|pop3|[110]",
		"*db2.DB2Plugin|db2|[446 50000]",
		"*pop3.TLSPlugin|pop3s|[995]",
		"*mysql.MYSQLPlugin|MySQL|[3306]",
		"*mssql.MSSQLPlugin|mssql|[1433]",
		"*sybase.SybasePlugin|sybase|[5000]",
		"*ldap.LDAPPlugin|ldap|[389]",
		"*ldap.TLSPlugin|ldaps|[636]",
		"*imap.TLSPlugin|imaps|[993]",
		"*imap.IMAPPlugin|imap|[143]",
		"*kafkanew.Plugin|kafkaNew|[9092]",
		"*kafkanew.TLSPlugin|KafkaNewTLS|[9093]",
		"*kafkaold.Plugin|kafkaOld|[9092]",
		"*kafkaold.TLSPlugin|KafkaOldTLS|[9093]",
		"*vnc.VNCPlugin|VNC|[5900]",
		"*linuxrpc.RPCPlugin|RPC|[111]",
		"*modbus.MODBUSPlugin|modbus|[502]",
		"*redis.REDISTLSPlugin|redis|[6380]",
		"*jdwp.JDWPPlugin|jdwp|[3999 5000 5005 8000 8453 8787 8788 9001 18000]",
		"*mqtt3.MQTT3Plugin|mqtt3|[1883]",
		"*mqtt3.TLSPlugin|mqtt3tls|[8883]",
		"*mqtt5.MQTT5Plugin|mqtt5|[1883]",
		"*mqtt5.TLSPlugin|mqtt5tls|[8883]",
		"*rsync.RSYNCPlugin|rsync|[873]",
		"*postgres.POSTGRESPlugin|postgres|[5432]",
		"*rtsp.RTSPPlugin|rtsp|[554]",
		"*http.HTTPPlugin|http|[80 3000 4567 5000 8000 8001 8080 8081 8888 9001 9080 9090 9100]",
		"*http.HTTPSPlugin|https|[443 8443 9443]",
	}
	if len(customFingerprintModules) != len(want) {
		t.Fatalf("TCP plugin count = %d, want %d", len(customFingerprintModules), len(want))
	}
	for i, p := range customFingerprintModules {
		got := fmt.Sprintf("%T|%s|%v", p, p.Name(), p.DefaultPorts())
		if got != want[i] {
			t.Errorf("TCP plugin %d = %q, want %q", i, got, want[i])
		}
	}
}

func TestUDPPluginRegistry(t *testing.T) {
	want := map[uint16]string{
		53:    "*plugins.DNSFingerprinter|dns|[53]",
		67:    "*plugins.DHCPFingerprinter|dhcp|[67]",
		69:    "*plugins.TFTPFingerprinter|tftp|[69]",
		123:   "*plugins.NTPFingerprinter|ntp|[123]",
		137:   "*plugins.NetBIOSFingerprinter|netbios-ns|[137]",
		161:   "*plugins.SNMPFingerprinter|snmp|[161 162]",
		162:   "*plugins.SNMPFingerprinter|snmp|[161 162]",
		177:   "*plugins.XdmcpFingerprinter|xdmcp|[177]",
		427:   "*plugins.SlpFingerprinter|slp|[427]",
		500:   "*plugins.IKEFingerprinter|ike|[500 4500]",
		623:   "*plugins.IPMIFingerprinter|ipmi|[623]",
		1194:  "*openvpn.Plugin|OpenVPN|[1194]",
		1812:  "*plugins.RADIUSFingerprinter|radius|[1812]",
		1900:  "*plugins.SSDPFingerprinter|ssdp|[1900]",
		2049:  "*plugins.NFSUDPFingerprinter|nfs-udp|[2049]",
		3478:  "*stun.Plugin|stun|[3478]",
		3702:  "*plugins.WSDiscoveryFingerprinter|ws-discovery|[3702]",
		4500:  "*plugins.IKEFingerprinter|ike|[500 4500]",
		5060:  "*plugins.SIPFingerprinter|sip|[5060]",
		5683:  "*plugins.CoAPFingerprinter|coap|[5683]",
		10001: "*plugins.UbiquitiFingerprinter|ubiquiti|[10001]",
		20000: "*plugins.DNP3UDPFingerprinter|dnp3-udp|[20000]",
		44818: "*plugins.EthernetIPUDPFingerprinter|ethernetip-udp|[44818]",
		47808: "*plugins.BACnetFingerprinter|bacnet|[47808]",
	}
	if len(udpFingerprinters) != len(want) {
		t.Fatalf("UDP port count = %d, want %d", len(udpFingerprinters), len(want))
	}
	for port, expected := range want {
		p, ok := udpFingerprinters[port]
		if !ok {
			t.Errorf("missing UDP port %d", port)
			continue
		}
		got := fmt.Sprintf("%T|%s|%v", p, p.Name(), p.DefaultPorts())
		if got != expected {
			t.Errorf("UDP port %d = %q, want %q", port, got, expected)
		}
	}
}
