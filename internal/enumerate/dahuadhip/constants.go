package dahuadhip

// defaultDahuaDhipPort is the canonical Dahua DHIP control-plane TCP port advertised
// in /cap.js as `capTcpPort` on Dahua web interfaces (TC-002/005/008/010/014 corpus).
const defaultDahuaDhipPort = 37777

// defaultDahuaDhipTimeoutMs caps the total end-to-end probe budget for one target.
const defaultDahuaDhipTimeoutMs = 10000

// dhipHeaderLen is the fixed 32-byte length of the DHIP packet header that prefixes
// every JSON-RPC body on the wire.  Layout (offsets, little-endian):
//
//	0  uint8[8]  magic  - 0xa0 0x05 0x00 0x00 0x00 0x00 0x00 0x00
//	8  uint64    sessionID - echoed across the connection (0 on initial probe)
//	16 uint32    bodyLen   - length of the JSON-RPC payload (excluding header)
//	20 uint32    bodyLenDup - identical to bodyLen on standard firmware
//	24 uint8[8]  reserved  - zero on initial probe
//
// Cross-referenced against the python-dahua-rpc and DahuaConsole open-source
// reverse-engineering corpora; see helpers.go for the parser.
const dhipHeaderLen = 32

// dhipResponseBodyCap bounds how many bytes of the JSON-RPC body we will read.
// In practice the global.login error response is well under 2 KB even on
// enterprise NVRs; cap higher than that and lower than 64 KB to keep memory
// bounded on hostile / honeypot peers.
const dhipResponseBodyCap = 8192

// dhipMagic is the leading byte sequence of every DHIP frame we expect to
// receive.  On non-DHIP listeners (e.g. anyone else binding TCP/37777) the
// first byte differs and we abort framing.
var dhipMagic = []byte{0xa0, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// dhipLoginProbeBody is the read-only `global.login` JSON-RPC payload sent on
// the initial probe.  The empty `password` causes Dahua firmware to reply
// with an authentication-challenge error that discloses the encryption mode
// and per-device realm WITHOUT mutating state — no credential brute-force is
// attempted (CVE-2021-33044 / CVE-2021-33045 territory is explicitly out of
// scope per AITF-125 hard rules).
//
// `clientType: "Web3.0"` is the User-Agent equivalent that newer firmware
// expects; older firmware accepts it as well per the python-dahua-rpc
// reference implementation.
const dhipLoginProbeBody = `{"method":"global.login","params":{"userName":"admin","password":"","clientType":"Web3.0","loginType":"Direct"},"id":1,"session":0}` + "\n"

// realmPlaintextSerialPattern matches the legacy Dahua plaintext-serial realm
// format observed on 2017-era firmware (TC-008): a 12-16 character uppercase
// alphanumeric string.  Modern firmware (2019+) hashes the realm to a 32-char
// hex value that we explicitly reject as "not a plaintext serial."
const realmPlaintextSerialMinLen = 12
const realmPlaintextSerialMaxLen = 16
