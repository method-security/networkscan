// Package socks provides SOCKS4/4a/5 protocol encoding and decoding utilities.
package socks

// SOCKS protocol version bytes
const (
	Version4 byte = 0x04
	Version5 byte = 0x05
)

// SOCKS command codes
const (
	CmdConnect      byte = 0x01
	CmdBind         byte = 0x02
	CmdUDPAssociate byte = 0x03
)

// SOCKS5 authentication method codes
const (
	AuthNoAuth           byte = 0x00
	AuthGSSAPI           byte = 0x01
	AuthUsernamePassword byte = 0x02
	AuthNoAcceptable     byte = 0xFF
)

// SOCKS5 address type codes
const (
	AtypIPv4   byte = 0x01
	AtypDomain byte = 0x03
	AtypIPv6   byte = 0x04
)

// SOCKS5 reply codes
const (
	RepSuccess            byte = 0x00
	RepGeneralFailure     byte = 0x01
	RepNotAllowed         byte = 0x02
	RepNetworkUnreachable byte = 0x03
	RepHostUnreachable    byte = 0x04
	RepConnectionRefused  byte = 0x05
	RepTTLExpired         byte = 0x06
	RepCmdNotSupported    byte = 0x07
	RepAtypNotSupported   byte = 0x08
)

// SOCKS4 reply codes
const (
	SOCKS4RepGranted  byte = 0x5A
	SOCKS4RepRejected byte = 0x5B
)

// SOCKS5 username/password sub-negotiation version
const AuthUsernamePasswordVersion byte = 0x01
