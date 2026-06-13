package ubiquitidiscovery

// defaultUbiquitiDiscoveryPort is the broadcast discovery port Ubiquiti devices
// listen on across AirOS, AirMAX, UniFi, and EdgeOS firmware families.
const defaultUbiquitiDiscoveryPort = 10001

// defaultUbiquitiDiscoveryTimeoutMs caps the end-to-end probe budget.  Discovery
// is a single-packet exchange so this only needs to cover one round-trip plus
// reasonable jitter.
const defaultUbiquitiDiscoveryTimeoutMs = 5000

// discoveryRequestV1 is the canonical v1 Ubiquiti Discovery request packet.
// Byte layout (4 bytes total):
//
//	0  version (0x01 = v1)
//	1  command (0x00 = discover)
//	2  payloadLen (0x00 — no payload)
//	3  payloadLen (0x00 — no payload)
//
// Reference: https://help.ui.com/hc/en-us/articles/204976244 (Ubiquiti
// official KB describing the wire format).  Cross-referenced against the
// community open-source `ubnt-discover` Python implementation.
var discoveryRequestV1 = []byte{0x01, 0x00, 0x00, 0x00}

// discoveryRequestV2 is the v2 Ubiquiti Discovery request — sent as a
// fallback when v1 elicits no response.  v2 was introduced with UniFi v3
// firmware and persists on modern AirOS / EdgeOS releases.
//
//	0  version (0x02 = v2)
//	1  command (0x08 = discover)
//	2  payloadLen (0x00)
//	3  payloadLen (0x00)
var discoveryRequestV2 = []byte{0x02, 0x08, 0x00, 0x00}

// discoveryResponseBodyCap bounds how many bytes of the TLV response we will
// read.  In practice responses are well under 1 KB even from chatty UniFi
// access points; cap higher to be safe against hostile peers.
const discoveryResponseBodyCap = 4096

// TLV record type codes per the published Discovery v1/v2 spec.  Not all
// firmware emits every record — the absence of a field is itself a fingerprint
// signal.
const (
	tlvTypeMacIPv1     = 0x01 // 10 bytes: 6 MAC + 4 IPv4
	tlvTypeMacIPv2     = 0x02 // 10 bytes: 6 MAC + 4 IPv4 (separate-LAN form)
	tlvTypeFirmwareLen = 0x03 // variable-length firmware version string
	tlvTypeUptime      = 0x0a // 4 bytes uptime in seconds (big-endian)
	tlvTypeHostname    = 0x0b // variable-length hostname string
	tlvTypePlatform    = 0x0c // variable-length platform / board name
	tlvTypeEssid       = 0x0d // variable-length ESSID (wireless only)
	tlvTypeModel       = 0x14 // variable-length model string
	tlvTypeVersion     = 0x15 // variable-length version (alternative format)
)
