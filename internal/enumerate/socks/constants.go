package socks

// Default probe target for SOCKS CONNECT tests (example.com)
const (
	DefaultProbeHost = "example.com"
	DefaultProbeIP   = "93.184.216.34"
	DefaultProbePort = uint16(80)
)

// Default timeouts
const (
	DefaultDialTimeoutSeconds  = 5
	DefaultProbeTimeoutSeconds = 5
)

// TOR well-known ports
var torPorts = map[int]bool{
	9050: true,
	9150: true,
}
