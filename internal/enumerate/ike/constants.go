package ike

// knownVendorIDs maps known IKE Vendor ID hex strings to human-readable names.
// These are MD5 hashes standardized by vendors for capability advertisement.
var knownVendorIDs = map[string]string{
	"afcad71368a1f1c96b8696fc77570100": "Dead Peer Detection (RFC 3706)",
	"4a131c81070358455c5728f20e95452f": "NAT-T (RFC 3947)",
	"cd60464335df21f87cfdb2fc68b6a448": "XAUTH",
	"12f5f28c457168a9702d9fe274cc0100": "Cisco Unity",
	"1e2b516905991c7d7c96fcbfb587e461": "Cisco VPN 3000",
	"c0f8f3a4c20f75ef0bb6a96a697d0aff": "Fortinet",
	"882fe56d6fd20dbc2251613b2ebe5beb": "strongSwan",
	"699369228741c6d4ca094c93e242c9de": "Microsoft Windows",
	"4048b7d56ebce88525e7de7f00d6c2d3": "Check Point",
}

// dpdVendorIDPrefix is the well-known prefix for Dead Peer Detection vendor IDs.
const dpdVendorIDPrefix = "afcad71368a1f1c96b8696fc7757"

// weakEncryptionAlgorithms are encryption algorithms considered cryptographically insecure.
var weakEncryptionAlgorithms = []string{
	"DES-CBC",
	"NULL",
}

// weakHashAlgorithms are hash/integrity algorithms considered cryptographically weak.
// Includes both IKEv2 names (PRF-HMAC-*, HMAC-*) and IKEv1 names (MD5, SHA1).
var weakHashAlgorithms = []string{
	"PRF-HMAC-MD5",
	"HMAC-MD5-96",
	"MD5",
	"PRF-HMAC-SHA1",
	"HMAC-SHA1-96",
	"SHA1",
}

// weakDHGroups are Diffie-Hellman groups that are too small to be secure.
var weakDHGroups = []string{
	"MODP-768",  // 768-bit, considered broken
	"MODP-1024", // 1024-bit, broken by Logjam attack
	"MODP-1536", // 1536-bit, considered marginal
}
