package service

import (
	"context"
	"net"

	discover "github.com/Method-Security/networkscan/generated/go/discover"
	localPlugins "github.com/Method-Security/networkscan/internal/discover/service/plugins"
	chromadb "github.com/Method-Security/networkscan/internal/discover/service/plugins/chromadb"
	couchdb "github.com/Method-Security/networkscan/internal/discover/service/plugins/couchdb"
	db2 "github.com/Method-Security/networkscan/internal/discover/service/plugins/db2"
	diameter "github.com/Method-Security/networkscan/internal/discover/service/plugins/diameter"
	echo "github.com/Method-Security/networkscan/internal/discover/service/plugins/echo"
	elasticsearch "github.com/Method-Security/networkscan/internal/discover/service/plugins/elasticsearch"
	firebird "github.com/Method-Security/networkscan/internal/discover/service/plugins/firebird"
	ftp "github.com/Method-Security/networkscan/internal/discover/service/plugins/ftp"
	http "github.com/Method-Security/networkscan/internal/discover/service/plugins/http"
	imap "github.com/Method-Security/networkscan/internal/discover/service/plugins/imap"
	influxdb "github.com/Method-Security/networkscan/internal/discover/service/plugins/influxdb"
	jdwp "github.com/Method-Security/networkscan/internal/discover/service/plugins/jdwp"
	kafkaNew "github.com/Method-Security/networkscan/internal/discover/service/plugins/kafka/kafkaNew"
	kafkaOld "github.com/Method-Security/networkscan/internal/discover/service/plugins/kafka/kafkaOld"
	kubernetes "github.com/Method-Security/networkscan/internal/discover/service/plugins/kubernetes"
	ldap "github.com/Method-Security/networkscan/internal/discover/service/plugins/ldap"
	linuxrpc "github.com/Method-Security/networkscan/internal/discover/service/plugins/linuxrpc"
	milvus "github.com/Method-Security/networkscan/internal/discover/service/plugins/milvus"
	modbus "github.com/Method-Security/networkscan/internal/discover/service/plugins/modbus"
	mqtt3 "github.com/Method-Security/networkscan/internal/discover/service/plugins/mqtt/mqtt3"
	mqtt5 "github.com/Method-Security/networkscan/internal/discover/service/plugins/mqtt/mqtt5"
	mssql "github.com/Method-Security/networkscan/internal/discover/service/plugins/mssql"
	mysql "github.com/Method-Security/networkscan/internal/discover/service/plugins/mysql"
	neo4j "github.com/Method-Security/networkscan/internal/discover/service/plugins/neo4j"
	openvpn "github.com/Method-Security/networkscan/internal/discover/service/plugins/openvpn"
	pinecone "github.com/Method-Security/networkscan/internal/discover/service/plugins/pinecone"
	pop3 "github.com/Method-Security/networkscan/internal/discover/service/plugins/pop3"
	postgresql "github.com/Method-Security/networkscan/internal/discover/service/plugins/postgresql"
	rdp "github.com/Method-Security/networkscan/internal/discover/service/plugins/rdp"
	redis "github.com/Method-Security/networkscan/internal/discover/service/plugins/redis"
	rsync "github.com/Method-Security/networkscan/internal/discover/service/plugins/rsync"
	rtsp "github.com/Method-Security/networkscan/internal/discover/service/plugins/rtsp"
	smpp "github.com/Method-Security/networkscan/internal/discover/service/plugins/smpp"
	smtp "github.com/Method-Security/networkscan/internal/discover/service/plugins/smtp"
	snpp "github.com/Method-Security/networkscan/internal/discover/service/plugins/snpp"
	stun "github.com/Method-Security/networkscan/internal/discover/service/plugins/stun"
	sybase "github.com/Method-Security/networkscan/internal/discover/service/plugins/sybase"
	telnet "github.com/Method-Security/networkscan/internal/discover/service/plugins/telnet"
	vnc "github.com/Method-Security/networkscan/internal/discover/service/plugins/vnc"
)

// Fingerprinter detects one application protocol at an endpoint.
type Fingerprinter interface {
	Name() string
	// An empty DefaultPorts list makes the plugin applicable on every TCP port.
	DefaultPorts() []int
	Detect(context.Context, net.IP, int, string, int) (*discover.ServiceDetails, error)
}

// tcpPlugins returns plugins in detection-priority order. Earlier matches win.
// Keep specific protocols before generic fallbacks, including S7Comm before MMS,
// JMX before Java RMI, UniStream before EtherNet/IP, and product probes before HTTP.
func tcpPlugins() []Fingerprinter {
	return []Fingerprinter{
		&localPlugins.SSHFingerprinter{},
		&localPlugins.DNSTCPFingerprinter{},
		&localPlugins.DNSTLSFingerprinter{},
		&localPlugins.EtcdFingerprinter{},
		&localPlugins.RedisFingerprinter{},
		&localPlugins.MongoDBFingerprinter{},
		&localPlugins.CassandraFingerprinter{},
		&localPlugins.BGPFingerprinter{},
		&localPlugins.DCERPCFingerprinter{},
		&localPlugins.IPPFingerprinter{},
		&localPlugins.WinRMFingerprinter{},
		&localPlugins.KerberosFingerprinter{},
		&localPlugins.SMBFingerprinter{},
		&localPlugins.FortiGateFingerprinter{},
		&localPlugins.PcworxFingerprinter{},
		&localPlugins.OpcuaFingerprinter{},
		&localPlugins.X11Fingerprinter{},
		&localPlugins.PcomFingerprinter{},
		&localPlugins.Iec104Fingerprinter{},
		&localPlugins.GesrtpFingerprinter{},
		&localPlugins.FinsFingerprinter{},
		&localPlugins.AtgFingerprinter{},
		&localPlugins.ArdFingerprinter{},
		&localPlugins.PptpFingerprinter{},
		&localPlugins.MsmqFingerprinter{},
		&localPlugins.S7CommFingerprinter{},
		&localPlugins.MmsFingerprinter{},
		&localPlugins.HartFingerprinter{},
		&localPlugins.FoxFingerprinter{},
		&localPlugins.MemcachedFingerprinter{},
		&localPlugins.UnistreamFingerprinter{},
		&localPlugins.EthernetIPFingerprinter{},
		&localPlugins.OracleFingerprinter{},
		&localPlugins.SMTPFingerprinter{},
		&localPlugins.JMXFingerprinter{},
		&localPlugins.JavaRMIFingerprinter{},
		&localPlugins.AJP13Fingerprinter{},
		&localPlugins.GrpcFingerprinter{},
		&localPlugins.WebLogicT3Fingerprinter{},
		&localPlugins.ZooKeeperFingerprinter{},
		&localPlugins.AMQPFingerprinter{},
		&localPlugins.NATSFingerprinter{},
		&localPlugins.BeanstalkdFingerprinter{},
		&localPlugins.ErlangEPMDFingerprinter{},
		&localPlugins.ADBFingerprinter{},
		&localPlugins.RTMPFingerprinter{},
		&localPlugins.SCCPFingerprinter{},
		&localPlugins.SOCKSFingerprinter{},
		&localPlugins.NNTPFingerprinter{},
		&localPlugins.IRCFingerprinter{},
		&localPlugins.XMPPFingerprinter{},
		&localPlugins.IdentFingerprinter{},
		&localPlugins.GopherFingerprinter{},
		&localPlugins.AFPFingerprinter{},
		&localPlugins.GitDaemonFingerprinter{},
		&localPlugins.FingerFingerprinter{},
		&localPlugins.WhoisFingerprinter{},
		&localPlugins.VMwareAuthdFingerprinter{},
		&localPlugins.PoppassdFingerprinter{},
		&localPlugins.JetDirectFingerprinter{},
		&localPlugins.LPDFingerprinter{},
		&localPlugins.RloginFingerprinter{},
		&localPlugins.DubboFingerprinter{},
		&localPlugins.TarantoolFingerprinter{},
		&localPlugins.DNP3Fingerprinter{},
		&localPlugins.MELSECFingerprinter{},
		&localPlugins.CodesysFingerprinter{},
		&localPlugins.BeckhoffADSFingerprinter{},
		&localPlugins.SAPRouterFingerprinter{},
		&localPlugins.NDMPFingerprinter{},
		&localPlugins.HPDataProtectorFingerprinter{},
		&localPlugins.NFSFingerprinter{},
		&localPlugins.WinboxFingerprinter{},
		&neo4j.NEO4JPlugin{},
		&neo4j.NEO4JTLSPlugin{},
		&echo.EchoPlugin{},
		&telnet.TELNETPlugin{},
		&ftp.FTPPlugin{},
		&snpp.SNPPPlugin{},
		&kubernetes.KubernetesPlugin{},
		&chromadb.ChromaDBPlugin{},
		&milvus.MilvusPlugin{},
		&pinecone.PINECONEPlugin{},
		&chromadb.ChromaDBTLSPlugin{},
		&milvus.MilvusMetricsPlugin{},
		&smpp.SMPPPlugin{},
		&diameter.DIAMETERPlugin{},
		&smtp.TLSPlugin{},
		&rdp.RDPPlugin{},
		&rdp.TLSPlugin{},
		&firebird.FirebirdPlugin{},
		&couchdb.COUCHDBPlugin{},
		&elasticsearch.ElasticsearchPlugin{},
		&influxdb.InfluxDBPlugin{},
		&couchdb.COUCHDBTLSPlugin{},
		&pop3.POP3Plugin{},
		&db2.DB2Plugin{},
		&pop3.TLSPlugin{},
		&mysql.MYSQLPlugin{},
		&mssql.MSSQLPlugin{},
		&sybase.SybasePlugin{},
		&ldap.LDAPPlugin{},
		&ldap.TLSPlugin{},
		&imap.TLSPlugin{},
		&imap.IMAPPlugin{},
		&kafkaNew.Plugin{},
		&kafkaNew.TLSPlugin{},
		&kafkaOld.Plugin{},
		&kafkaOld.TLSPlugin{},
		&vnc.VNCPlugin{},
		&linuxrpc.RPCPlugin{},
		&modbus.MODBUSPlugin{},
		&redis.REDISTLSPlugin{},
		&jdwp.JDWPPlugin{},
		&mqtt3.MQTT3Plugin{},
		&mqtt3.TLSPlugin{},
		&mqtt5.MQTT5Plugin{},
		&mqtt5.TLSPlugin{},
		&rsync.RSYNCPlugin{},
		&postgresql.POSTGRESPlugin{},
		&rtsp.RTSPPlugin{},
		&http.HTTPPlugin{},
		&http.HTTPSPlugin{},
	}
}

// udpPlugins maps every supported UDP port to its probe; no other ports are attempted.
func udpPlugins() map[uint16]Fingerprinter {
	return map[uint16]Fingerprinter{
		53:    &localPlugins.DNSFingerprinter{},
		67:    &localPlugins.DHCPFingerprinter{},
		69:    &localPlugins.TFTPFingerprinter{},
		123:   &localPlugins.NTPFingerprinter{},
		137:   &localPlugins.NetBIOSFingerprinter{},
		161:   &localPlugins.SNMPFingerprinter{},
		162:   &localPlugins.SNMPFingerprinter{},
		177:   &localPlugins.XdmcpFingerprinter{},
		427:   &localPlugins.SlpFingerprinter{},
		500:   &localPlugins.IKEFingerprinter{},
		623:   &localPlugins.IPMIFingerprinter{},
		1194:  &openvpn.Plugin{},
		1812:  &localPlugins.RADIUSFingerprinter{},
		1900:  &localPlugins.SSDPFingerprinter{},
		2049:  &localPlugins.NFSUDPFingerprinter{},
		3478:  &stun.Plugin{},
		3702:  &localPlugins.WSDiscoveryFingerprinter{},
		4500:  &localPlugins.IKEFingerprinter{},
		5060:  &localPlugins.SIPFingerprinter{},
		5683:  &localPlugins.CoAPFingerprinter{},
		10001: &localPlugins.UbiquitiFingerprinter{},
		20000: &localPlugins.DNP3UDPFingerprinter{},
		44818: &localPlugins.EthernetIPUDPFingerprinter{},
		47808: &localPlugins.BACnetFingerprinter{},
	}
}

var (
	customFingerprintModules = tcpPlugins()
	udpFingerprinters        = udpPlugins()
)
