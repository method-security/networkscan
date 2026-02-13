//go:build windows

// Package udpsocket provides platform-specific UDP socket operations for traceroute.
package udpsocket

import (
	"fmt"
	"net"
	"syscall"
)

// SetUDPSocketTTL sets the TTL (Time To Live) on a UDP socket for Windows systems.
// This is used for traceroute to control how many hops a packet can travel.
func SetUDPSocketTTL(conn *net.UDPConn, ttl int) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get raw connection: %w", err)
	}

	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		// On Windows, file descriptors are syscall.Handle (uintptr)
		sockErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	})
	if err != nil {
		return fmt.Errorf("failed to set TTL: %w", err)
	}
	if sockErr != nil {
		return fmt.Errorf("failed to set TTL: %w", sockErr)
	}

	return nil
}
