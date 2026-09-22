// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Protocol metadata adapted for networkscan.
package probe

import (
	"net/http"
)

type ServiceSMTPS struct {
	Banner      string   `json:"banner"`
	AuthMethods []string `json:"authMethods"`
}

func (ServiceSMTPS) Type() string { return "smtps" }

type ServiceIMAP struct {
	Banner string `json:"banner"`
}

func (ServiceIMAP) Type() string { return "imap" }

type ServicePOP3S struct {
	Banner string `json:"banner"`
}

func (ServicePOP3S) Type() string { return "pop3s" }

const ProtoDB2 = "db2"
const ProtoChromaDB = "chromadb"
const ProtoCouchDB = "couchdb"
const ProtoEcho = "echo"
const ProtoElasticsearch = "elasticsearch"
const ProtoFirebird = "firebird"
const ProtoFTP = "ftp"
const ProtoHTTP = "http"
const ProtoHTTPS = "https"
const ProtoIMAPS = "imaps"
const ProtoInfluxDB = "influxdb"
const ProtoJDWP = "jdwp"
const ProtoKafka = "kafka"
const ProtoKubernetes = "kubernetes"
const ProtoLDAP = "ldap"
const ProtoLDAPS = "ldaps"
const ProtoMilvus = "milvus"
const ProtoMilvusMetrics = "milvus-metrics"
const ProtoModbus = "modbus"
const ProtoMQTT = "mqtt"
const ProtoMSSQL = "mssql"
const ProtoMySQL = "mysql"
const ProtoNeo4j = "neo4j"
const ProtoOpenVPN = "openvpn"
const ProtoPinecone = "pinecone"
const ProtoPOP3 = "pop3"
const ProtoPostgreSQL = "postgresql"
const ProtoRDP = "rdp"
const ProtoRPC = "rpc"
const ProtoRedis = "redis"
const ProtoRsync = "rsync"
const ProtoRtsp = "rtsp"
const ProtoSMPP = "smpp"
const ProtoSMTP = "smtp"
const ProtoSNPP = "snpp"
const ProtoStun = "stun"
const ProtoSybase = "sybase"
const ProtoTelnet = "telnet"
const ProtoVNC = "vnc"

type ServiceHTTP struct {
	Status          string      `json:"status"`
	StatusCode      int         `json:"statusCode"`
	ResponseHeaders http.Header `json:"responseHeaders"`
	Technologies    []string    `json:"technologies,omitempty"`
	CPEs            []string    `json:"cpes,omitempty"`
}

func (e ServiceHTTP) Type() string { return ProtoHTTP }

type ServiceHTTPS struct {
	Status          string      `json:"status"`
	StatusCode      int         `json:"statusCode"`
	ResponseHeaders http.Header `json:"responseHeaders"`
	Technologies    []string    `json:"technologies,omitempty"`
	CPEs            []string    `json:"cpes,omitempty"`
}

func (e ServiceHTTPS) Type() string { return ProtoHTTPS }

type ServiceRDP struct {
	OSFingerprint       string `json:"fingerprint,omitempty"`
	OSVersion           string `json:"osVersion,omitempty"`
	TargetName          string `json:"targetName,omitempty"`
	NetBIOSComputerName string `json:"netBIOSComputerName,omitempty"`
	NetBIOSDomainName   string `json:"netBIOSDomainName,omitempty"`
	DNSComputerName     string `json:"dnsComputerName,omitempty"`
	DNSDomainName       string `json:"dnsDomainName,omitempty"`
	ForestName          string `json:"forestName,omitempty"`
}

func (e ServiceRDP) Type() string { return ProtoRDP }

type ServiceRPC struct {
	Entries []RPCB `json:"entries"`
}
type RPCB struct {
	Program  int    `json:"program"`
	Version  int    `json:"version"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Owner    string `json:"owner"`
}

func (e ServiceRPC) Type() string { return ProtoRPC }

type ServiceMySQL struct {
	PacketType   string   `json:"packetType"`
	ErrorMessage string   `json:"errorMsg"`
	ErrorCode    int      `json:"errorCode"`
	CPEs         []string `json:"cpes,omitempty"`
}

func (e ServiceMySQL) Type() string      { return ProtoMySQL }
func (e ServicePostgreSQL) Type() string { return ProtoPostgreSQL }

type ServicePostgreSQL struct {
	AuthRequired bool     `json:"authRequired"`
	CPEs         []string `json:"cpes,omitempty"`
}
type ServicePOP3 struct {
	Banner string `json:"banner"`
}

func (e ServicePOP3) Type() string { return ProtoPOP3 }

type ServiceSNPP struct {
	Banner string `json:"banner"`
}

func (e ServiceSNPP) Type() string { return ProtoSNPP }

type ServiceIMAPS struct {
	Banner string `json:"banner"`
}

func (e ServiceIMAPS) Type() string { return ProtoIMAPS }

type ServiceInfluxDB struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceInfluxDB) Type() string { return ProtoInfluxDB }

type ServiceMSSQL struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceMSSQL) Type() string { return ProtoMSSQL }

type ServiceVNC struct{}

func (e ServiceVNC) Type() string { return ProtoVNC }

type ServiceTelnet struct {
	ServerData string `json:"serverData"`
}

func (e ServiceTelnet) Type() string { return ProtoTelnet }

type ServiceRedis struct {
	AuthRequired bool     `json:"authRequired"`
	CPEs         []string `json:"cpes,omitempty"`
}

func (e ServiceRedis) Type() string { return ProtoRedis }

type ServiceElasticsearch struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceElasticsearch) Type() string { return ProtoElasticsearch }

type ServiceFTP struct {
	Banner     string   `json:"banner"`
	Confidence string   `json:"confidence,omitempty"`
	CPEs       []string `json:"cpes,omitempty"`
}

func (e ServiceFTP) Type() string { return ProtoFTP }

type ServiceSMPP struct {
	CPEs            []string `json:"cpes,omitempty"`
	ProtocolVersion string   `json:"protocolVersion,omitempty"`
	SystemID        string   `json:"systemID,omitempty"`
	Vendor          string   `json:"vendor,omitempty"`
	Product         string   `json:"product,omitempty"`
}

func (e ServiceSMPP) Type() string { return ProtoSMPP }

type ServiceSMTP struct {
	Banner      string   `json:"banner"`
	AuthMethods []string `json:"auth_methods"`
}

func (e ServiceSMTP) Type() string { return ProtoSMTP }

type ServiceStun struct {
	Info string `json:"info"`
}

func (e ServiceStun) Type() string { return ProtoStun }

type ServiceSybase struct {
	CPEs    []string `json:"cpes,omitempty"`
	Version string   `json:"version,omitempty"`
}

func (e ServiceSybase) Type() string { return ProtoSybase }

type ServiceLDAP struct{}

func (e ServiceLDAP) Type() string { return ProtoLDAP }

type ServiceLDAPS struct{}

func (e ServiceLDAPS) Type() string { return ProtoLDAPS }

type ServiceKafka struct{}

func (e ServiceKafka) Type() string { return ProtoKafka }

type ServiceKubernetes struct {
	CPEs         []string `json:"cpes,omitempty"`
	GitVersion   string   `json:"gitVersion,omitempty"`
	GitCommit    string   `json:"gitCommit,omitempty"`
	BuildDate    string   `json:"buildDate,omitempty"`
	GoVersion    string   `json:"goVersion,omitempty"`
	Platform     string   `json:"platform,omitempty"`
	Distribution string   `json:"distribution,omitempty"`
	Vendor       string   `json:"vendor,omitempty"`
}

func (e ServiceKubernetes) Type() string { return ProtoKubernetes }

type ServicePinecone struct {
	CPEs       []string `json:"cpes,omitempty"`
	APIVersion string   `json:"apiVersion,omitempty"`
}

func (e ServicePinecone) Type() string { return ProtoPinecone }

type ServiceOpenVPN struct{}

func (e ServiceOpenVPN) Type() string { return ProtoOpenVPN }

type ServiceMQTT struct{}

func (e ServiceMQTT) Type() string { return ProtoMQTT }

type ServiceMilvus struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceMilvus) Type() string { return ProtoMilvus }

type ServiceMilvusMetrics struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceMilvusMetrics) Type() string { return ProtoMilvusMetrics }

type ServiceModbus struct{}

func (e ServiceModbus) Type() string { return ProtoModbus }

type ServiceNeo4j struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceNeo4j) Type() string { return ProtoNeo4j }

type ServiceRtsp struct {
	ServerInfo string `json:"serverInfo"`
}

func (e ServiceRtsp) Type() string { return ProtoRtsp }

type ServiceCouchDB struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceCouchDB) Type() string { return ProtoCouchDB }

type ServiceDB2 struct {
	ServerName string   `json:"serverName,omitempty"`
	CPEs       []string `json:"cpes,omitempty"`
}

func (e ServiceDB2) Type() string { return ProtoDB2 }

type ServiceChromaDB struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceChromaDB) Type() string { return ProtoChromaDB }

type ServiceEcho struct{}

func (e ServiceEcho) Type() string { return ProtoEcho }

type ServiceFirebird struct {
	ProtocolVersion int32    `json:"protocol_version,omitempty"`
	CPEs            []string `json:"cpes,omitempty"`
}

func (e ServiceFirebird) Type() string { return ProtoFirebird }

type ServiceRsync struct{}

func (e ServiceRsync) Type() string { return ProtoRsync }

type ServiceJDWP struct {
	Description string `json:"description"`
	JdwpMajor   int32  `json:"jdwpMajor"`
	JdwpMinor   int32  `json:"jdwpMinor"`
	VMVersion   string `json:"VMVersion"`
	VMName      string `json:"VMName"`
}

func (e ServiceJDWP) Type() string { return ProtoJDWP }
