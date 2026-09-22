# Service Plugin Coverage

Audited against the pinned fingerprintx Go SDK **v1.1.19** and upstream GitHub
commit **48019490954a735898405a4aa304067a18d8ee7b**. The registered Go plugins,
not just the upstream README, are the source of truth. The latter omits some
variants, including Kubernetes and Milvus metrics.

| Protocols | Networkscan implementation |
| --- | --- |
| SSH, Cassandra, MongoDB, Memcached, Oracle, Java RMI, SMB, SMTP, Redis | Existing specialized TCP plugins retained; Redis TLS and SMTP TLS added |
| DNS | Existing UDP and TLS plugins retained; TCP plugin added |
| DHCP, IPMI, NetBIOS, NTP, SNMP | Existing UDP plugins retained |
| IPsec | Existing IKE plugin retained on 500/4500; emitted protocol stays IKE |
| HTTP/HTTPS, LDAP/LDAPS | Added general-discovery probes; existing targeted service-type behavior retained |
| Echo, FTP, IMAP/IMAPS, POP3/POP3S, JDWP, Linux RPC, Modbus, MySQL, MSSQL, PostgreSQL, RDP, Rsync, RTSP, SNPP, Telnet, VNC | Added local TCP probes |
| Kafka old/new, MQTT 3/5 | Added local plaintext and TLS probes |
| OpenVPN, STUN | Added UDP probes on 1194 and 3478 |
| ChromaDB, CouchDB, DB2, Diameter, Elasticsearch, Firebird, InfluxDB, Kubernetes, Milvus (API and metrics), Neo4j, Pinecone, SMPP, Sybase | Added probes present in upstream GitHub beyond the pinned SDK; TLS variants retained where upstream provides them |

## Execution and Output

TCP first tries plugins whose default ports match the target, then tries the
remaining plugins on non-default ports. The separate fingerprintx phase is
removed. Existing networkscan plugins keep precedence; specific new products
precede generic HTTP in the new probe list. Each attempt uses the existing
per-plugin timeout and `plugin-threads` budget; `threads` still limits targets.
UDP still probes each supported service only on its configured ports.

Defaults stay at 10 target threads, 10 plugin threads, and a 30-second timeout.
The config/result/errors report shape stays unchanged. New protocol enum values
are declared in Fern so SDK generation includes them. Downstream consumers must
support those additional enums to model the newly detected applications.

This is protocol coverage parity, not a claim that every server implementation
is identifiable. For example, OpenVPN with tls-auth can silently discard probes,
and authentication, filtering, and service versions can prevent detection.

## Dependency Boundary

Service discovery and port validation no longer import or invoke fingerprintx.
The Nuclei dependency still imports its protocol helpers for JavaScript template
execution. It remains an indirect dependency pinned at the existing v1.1.19;
the unused scanner and unrelated vendored plugin code are removed. Removing
Nuclei's remaining imports requires a separate dependency migration.

## Verification

Parser tests cover the imported protocol implementations. Loopback tests cover
TCP and UDP exchanges, implicit TLS, SNI and Host preservation, redirects,
malformed replies, and cancellation of every new TCP probe. No Shodan or other
external scan targets are used in these tests.
