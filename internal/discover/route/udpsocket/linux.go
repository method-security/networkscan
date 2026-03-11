//go:build unix || darwin || linux || freebsd || openbsd || netbsd

// Package udpsocket provides platform-specific UDP socket operations for traceroute.
package udpsocket

import (
	"fmt"
	"net"
	"syscall"
)

// SetUDPSocketTTL sets the TTL (Time To Live) or Hop Limit on a UDP socket for Unix-like systems.
// For IPv4, this sets IP_TTL. For IPv6, this sets IPV6_UNICAST_HOPS.
func SetUDPSocketTTL(conn *net.UDPConn, ttl int) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get raw connection: %w", err)
	}

	isIPv6 := conn.LocalAddr().(*net.UDPAddr).IP.To4() == nil

	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		if isIPv6 {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
		} else {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		}
	})
	if err != nil {
		return fmt.Errorf("failed to set TTL: %w", err)
	}
	if sockErr != nil {
		return fmt.Errorf("failed to set TTL: %w", sockErr)
	}

	return nil
}
