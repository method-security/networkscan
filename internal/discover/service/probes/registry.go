package probes

import (
	"context"
	"net"
	"sort"

	discover "github.com/Method-Security/networkscan/generated/go/discover"
	chromadb "github.com/Method-Security/networkscan/internal/discover/service/probes/chromadb"
	couchdb "github.com/Method-Security/networkscan/internal/discover/service/probes/couchdb"
	db2 "github.com/Method-Security/networkscan/internal/discover/service/probes/db2"
	diameter "github.com/Method-Security/networkscan/internal/discover/service/probes/diameter"
	echo "github.com/Method-Security/networkscan/internal/discover/service/probes/echo"
	elasticsearch "github.com/Method-Security/networkscan/internal/discover/service/probes/elasticsearch"
	firebird "github.com/Method-Security/networkscan/internal/discover/service/probes/firebird"
	ftp "github.com/Method-Security/networkscan/internal/discover/service/probes/ftp"
	http "github.com/Method-Security/networkscan/internal/discover/service/probes/http"
	imap "github.com/Method-Security/networkscan/internal/discover/service/probes/imap"
	influxdb "github.com/Method-Security/networkscan/internal/discover/service/probes/influxdb"
	jdwp "github.com/Method-Security/networkscan/internal/discover/service/probes/jdwp"
	kafkaNew "github.com/Method-Security/networkscan/internal/discover/service/probes/kafka/kafkaNew"
	kafkaOld "github.com/Method-Security/networkscan/internal/discover/service/probes/kafka/kafkaOld"
	kubernetes "github.com/Method-Security/networkscan/internal/discover/service/probes/kubernetes"
	ldap "github.com/Method-Security/networkscan/internal/discover/service/probes/ldap"
	linuxrpc "github.com/Method-Security/networkscan/internal/discover/service/probes/linuxrpc"
	milvus "github.com/Method-Security/networkscan/internal/discover/service/probes/milvus"
	modbus "github.com/Method-Security/networkscan/internal/discover/service/probes/modbus"
	mqtt3 "github.com/Method-Security/networkscan/internal/discover/service/probes/mqtt/mqtt3"
	mqtt5 "github.com/Method-Security/networkscan/internal/discover/service/probes/mqtt/mqtt5"
	mssql "github.com/Method-Security/networkscan/internal/discover/service/probes/mssql"
	mysql "github.com/Method-Security/networkscan/internal/discover/service/probes/mysql"
	neo4j "github.com/Method-Security/networkscan/internal/discover/service/probes/neo4j"
	pinecone "github.com/Method-Security/networkscan/internal/discover/service/probes/pinecone"
	pop3 "github.com/Method-Security/networkscan/internal/discover/service/probes/pop3"
	postgresql "github.com/Method-Security/networkscan/internal/discover/service/probes/postgresql"
	"github.com/Method-Security/networkscan/internal/discover/service/probes/probe"
	rdp "github.com/Method-Security/networkscan/internal/discover/service/probes/rdp"
	redis "github.com/Method-Security/networkscan/internal/discover/service/probes/redis"
	rsync "github.com/Method-Security/networkscan/internal/discover/service/probes/rsync"
	rtsp "github.com/Method-Security/networkscan/internal/discover/service/probes/rtsp"
	smpp "github.com/Method-Security/networkscan/internal/discover/service/probes/smpp"
	smtp "github.com/Method-Security/networkscan/internal/discover/service/probes/smtp"
	snpp "github.com/Method-Security/networkscan/internal/discover/service/probes/snpp"
	sybase "github.com/Method-Security/networkscan/internal/discover/service/probes/sybase"
	telnet "github.com/Method-Security/networkscan/internal/discover/service/probes/telnet"
	vnc "github.com/Method-Security/networkscan/internal/discover/service/probes/vnc"
)

type Fingerprinter interface {
	Name() string
	DefaultPorts() []int
	Detect(context.Context, net.IP, int, string, int) (*discover.ServiceDetails, error)
}

func TCP() []Fingerprinter {
	all := []wireFingerprinter{
		&echo.EchoPlugin{},
		&ftp.FTPPlugin{},
		&http.HTTPPlugin{},
		&http.HTTPSPlugin{},
		&imap.IMAPPlugin{},
		&imap.TLSPlugin{},
		&jdwp.JDWPPlugin{},
		&kafkaNew.Plugin{},
		&kafkaNew.TLSPlugin{},
		&kafkaOld.Plugin{},
		&kafkaOld.TLSPlugin{},
		&ldap.LDAPPlugin{},
		&ldap.TLSPlugin{},
		&linuxrpc.RPCPlugin{},
		&modbus.MODBUSPlugin{},
		&mqtt3.MQTT3Plugin{},
		&mqtt3.TLSPlugin{},
		&mqtt5.MQTT5Plugin{},
		&mqtt5.TLSPlugin{},
		&mssql.MSSQLPlugin{},
		&mysql.MYSQLPlugin{},
		&pop3.POP3Plugin{},
		&pop3.TLSPlugin{},
		&postgresql.POSTGRESPlugin{},
		&rdp.RDPPlugin{},
		&rdp.TLSPlugin{},
		&redis.REDISTLSPlugin{},
		&rsync.RSYNCPlugin{},
		&rtsp.RTSPPlugin{},
		&smtp.TLSPlugin{},
		&snpp.SNPPPlugin{},
		&telnet.TELNETPlugin{},
		&vnc.VNCPlugin{},
		&db2.DB2Plugin{},
		&diameter.DIAMETERPlugin{},
		&firebird.FirebirdPlugin{},
		&sybase.SybasePlugin{},
		&smpp.SMPPPlugin{},
		&chromadb.ChromaDBPlugin{},
		&chromadb.ChromaDBTLSPlugin{},
		&couchdb.COUCHDBPlugin{},
		&couchdb.COUCHDBTLSPlugin{},
		&elasticsearch.ElasticsearchPlugin{},
		&influxdb.InfluxDBPlugin{},
		&milvus.MilvusPlugin{},
		&milvus.MilvusMetricsPlugin{},
		&neo4j.NEO4JPlugin{},
		&neo4j.NEO4JTLSPlugin{},
		&pinecone.PINECONEPlugin{},
		&kubernetes.KubernetesPlugin{},
	}
	// Product-specific HTTP protocols must beat generic HTTP on overlapping ports.
	sort.SliceStable(all, func(i, j int) bool {
		priority := func(p wireFingerprinter) int {
			if p.Name() == "http" || p.Name() == "https" {
				return 10000
			}
			return p.Priority()
		}
		return priority(all[i]) < priority(all[j])
	})
	out := make([]Fingerprinter, 0, len(all))
	for _, p := range all {
		if p.Type() != probe.UDP {
			out = append(out, p)
		}
	}
	return out
}

type wireFingerprinter interface {
	Fingerprinter
	Type() probe.Protocol
	Priority() int
}
