package socks

import (
	// Standard
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// BuildSOCKS4ConnectRequest builds a SOCKS4 CONNECT request for the given IP and port.
// userid is the user identifier string (may be empty).
func BuildSOCKS4ConnectRequest(ip net.IP, port uint16, userid string) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4(1, 1, 1, 1).To4()
	}
	buf := make([]byte, 0, 9+len(userid))
	buf = append(buf, Version4, CmdConnect)
	buf = append(buf, byte(port>>8), byte(port))
	buf = append(buf, ip4...)
	buf = append(buf, []byte(userid)...)
	buf = append(buf, 0x00)
	return buf
}

// BuildSOCKS4aConnectRequest builds a SOCKS4a CONNECT request for the given hostname and port.
// SOCKS4a uses a special IP (0.0.0.0/0.0.0.1) and appends the hostname after the userid.
func BuildSOCKS4aConnectRequest(hostname string, port uint16, userid string) []byte {
	// Use IP 0.0.0.0.1 to signal SOCKS4a (non-routable, last octet non-zero)
	fakeIP := []byte{0x00, 0x00, 0x00, 0x01}
	buf := make([]byte, 0, 9+len(userid)+len(hostname)+1)
	buf = append(buf, Version4, CmdConnect)
	buf = append(buf, byte(port>>8), byte(port))
	buf = append(buf, fakeIP...)
	buf = append(buf, []byte(userid)...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte(hostname)...)
	buf = append(buf, 0x00)
	return buf
}

// ParseSOCKS4Reply reads and parses an 8-byte SOCKS4 reply.
// Returns the reply code and bound address/port.
func ParseSOCKS4Reply(r io.Reader) (replyCode byte, boundIP net.IP, boundPort uint16, err error) {
	reply := make([]byte, 8)
	if _, err = io.ReadFull(r, reply); err != nil {
		return 0, nil, 0, fmt.Errorf("reading SOCKS4 reply: %w", err)
	}
	if reply[0] != 0x00 {
		return 0, nil, 0, fmt.Errorf("unexpected SOCKS4 reply version byte: 0x%02x", reply[0])
	}
	replyCode = reply[1]
	boundPort = binary.BigEndian.Uint16(reply[2:4])
	boundIP = net.IP(reply[4:8])
	return replyCode, boundIP, boundPort, nil
}

// BuildSOCKS5Greeting builds a SOCKS5 client greeting offering the specified auth methods.
func BuildSOCKS5Greeting(methods []byte) []byte {
	buf := make([]byte, 0, 2+len(methods))
	buf = append(buf, Version5, byte(len(methods)))
	buf = append(buf, methods...)
	return buf
}

// ParseSOCKS5ServerChoice reads the SOCKS5 server's method selection reply.
// Returns the chosen auth method byte.
func ParseSOCKS5ServerChoice(r io.Reader) (method byte, err error) {
	reply := make([]byte, 2)
	if _, err = io.ReadFull(r, reply); err != nil {
		return 0, fmt.Errorf("reading SOCKS5 server choice: %w", err)
	}
	if reply[0] != Version5 {
		return 0, fmt.Errorf("unexpected SOCKS5 version byte: 0x%02x", reply[0])
	}
	return reply[1], nil
}

// BuildSOCKS5ConnectRequest builds a SOCKS5 CONNECT request using an IPv4 address.
func BuildSOCKS5ConnectRequest(ip net.IP, port uint16) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4(93, 184, 216, 34).To4()
	}
	buf := make([]byte, 0, 10)
	buf = append(buf, Version5, CmdConnect, 0x00, AtypIPv4)
	buf = append(buf, ip4...)
	buf = append(buf, byte(port>>8), byte(port))
	return buf
}

// BuildSOCKS5ConnectRequestDomain builds a SOCKS5 CONNECT request using a domain name.
func BuildSOCKS5ConnectRequestDomain(hostname string, port uint16) []byte {
	buf := make([]byte, 0, 7+len(hostname))
	buf = append(buf, Version5, CmdConnect, 0x00, AtypDomain)
	buf = append(buf, byte(len(hostname)))
	buf = append(buf, []byte(hostname)...)
	buf = append(buf, byte(port>>8), byte(port))
	return buf
}

// BuildSOCKS5BindRequest builds a SOCKS5 BIND request.
func BuildSOCKS5BindRequest(ip net.IP, port uint16) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = []byte{0, 0, 0, 0}
	}
	buf := make([]byte, 0, 10)
	buf = append(buf, Version5, CmdBind, 0x00, AtypIPv4)
	buf = append(buf, ip4...)
	buf = append(buf, byte(port>>8), byte(port))
	return buf
}

// BuildSOCKS5UDPAssociateRequest builds a SOCKS5 UDP ASSOCIATE request.
func BuildSOCKS5UDPAssociateRequest(ip net.IP, port uint16) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = []byte{0, 0, 0, 0}
	}
	buf := make([]byte, 0, 10)
	buf = append(buf, Version5, CmdUDPAssociate, 0x00, AtypIPv4)
	buf = append(buf, ip4...)
	buf = append(buf, byte(port>>8), byte(port))
	return buf
}

// ParseSOCKS5Reply reads and parses a SOCKS5 reply.
// Returns the reply code, bound address, and bound port.
func ParseSOCKS5Reply(r io.Reader) (repCode byte, bndAddr string, bndPort uint16, err error) {
	// Read VER, REP, RSV, ATYP
	header := make([]byte, 4)
	if _, err = io.ReadFull(r, header); err != nil {
		return 0, "", 0, fmt.Errorf("reading SOCKS5 reply header: %w", err)
	}
	if header[0] != Version5 {
		return 0, "", 0, fmt.Errorf("unexpected SOCKS5 reply version: 0x%02x", header[0])
	}
	repCode = header[1]
	atyp := header[3]

	switch atyp {
	case AtypIPv4:
		addr := make([]byte, 4)
		if _, err = io.ReadFull(r, addr); err != nil {
			return repCode, "", 0, fmt.Errorf("reading IPv4 BND.ADDR: %w", err)
		}
		portBytes := make([]byte, 2)
		if _, err = io.ReadFull(r, portBytes); err != nil {
			return repCode, "", 0, fmt.Errorf("reading BND.PORT: %w", err)
		}
		bndAddr = net.IP(addr).String()
		bndPort = binary.BigEndian.Uint16(portBytes)
	case AtypDomain:
		lenByte := make([]byte, 1)
		if _, err = io.ReadFull(r, lenByte); err != nil {
			return repCode, "", 0, fmt.Errorf("reading domain length: %w", err)
		}
		domain := make([]byte, lenByte[0])
		if _, err = io.ReadFull(r, domain); err != nil {
			return repCode, "", 0, fmt.Errorf("reading domain: %w", err)
		}
		portBytes := make([]byte, 2)
		if _, err = io.ReadFull(r, portBytes); err != nil {
			return repCode, "", 0, fmt.Errorf("reading BND.PORT: %w", err)
		}
		bndAddr = string(domain)
		bndPort = binary.BigEndian.Uint16(portBytes)
	case AtypIPv6:
		addr := make([]byte, 16)
		if _, err = io.ReadFull(r, addr); err != nil {
			return repCode, "", 0, fmt.Errorf("reading IPv6 BND.ADDR: %w", err)
		}
		portBytes := make([]byte, 2)
		if _, err = io.ReadFull(r, portBytes); err != nil {
			return repCode, "", 0, fmt.Errorf("reading BND.PORT: %w", err)
		}
		bndAddr = net.IP(addr).String()
		bndPort = binary.BigEndian.Uint16(portBytes)
	default:
		return repCode, "", 0, fmt.Errorf("unknown ATYP: 0x%02x", atyp)
	}

	return repCode, bndAddr, bndPort, nil
}

// BuildSOCKS5UsernamePasswordAuth builds a SOCKS5 username/password auth sub-negotiation request.
func BuildSOCKS5UsernamePasswordAuth(username, password string) []byte {
	buf := make([]byte, 0, 3+len(username)+len(password))
	buf = append(buf, AuthUsernamePasswordVersion)
	buf = append(buf, byte(len(username)))
	buf = append(buf, []byte(username)...)
	buf = append(buf, byte(len(password)))
	buf = append(buf, []byte(password)...)
	return buf
}

// ParseSOCKS5AuthReply reads the SOCKS5 username/password auth reply.
// Returns true if authentication was successful (status == 0x00).
func ParseSOCKS5AuthReply(r io.Reader) (success bool, err error) {
	reply := make([]byte, 2)
	if _, err = io.ReadFull(r, reply); err != nil {
		return false, fmt.Errorf("reading auth reply: %w", err)
	}
	return reply[1] == 0x00, nil
}

// BuildSOCKS5UDPRequest builds a SOCKS5 UDP request encapsulation header.
func BuildSOCKS5UDPRequest(ip net.IP, port uint16, data []byte) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = []byte{0, 0, 0, 0}
	}
	// RSV(2) + FRAG(1) + ATYP(1) + ADDR(4) + PORT(2) + DATA
	buf := make([]byte, 0, 10+len(data))
	buf = append(buf, 0x00, 0x00, 0x00, AtypIPv4)
	buf = append(buf, ip4...)
	buf = append(buf, byte(port>>8), byte(port))
	buf = append(buf, data...)
	return buf
}
