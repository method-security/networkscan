// Copyright 2024 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build !windows
// +build !windows

package pcap

import (
	"syscall"

	"golang.org/x/sys/unix"
)

const errorBufferSize = 0x100

const (
	pcapErrorNotActivated    = -3
	pcapErrorActivated       = -4
	pcapWarningPromisc       = 2
	pcapErrorNoSuchDevice    = -5
	pcapErrorDenied          = -8
	pcapErrorNotUp           = -9
	pcapError                = -1
	pcapWarning              = 1
	pcapDIN                  = 1
	pcapDOUT                 = 2
	pcapDINOUT               = 0
	pcapNetmaskUnknown       = 0xffffffff
	pcapTstampPrecisionMicro = 0
	pcapTstampPrecisionNano  = 1
)

// pcapPkthdr mirrors C's struct pcap_pkthdr.
// Using unix.Timeval ensures correct field sizes and alignment per OS/arch.
type pcapPkthdr struct {
	Ts     unix.Timeval
	Caplen uint32
	Len    uint32
}

type pcapTPtr uintptr

type pcapBpfInstruction struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// pcapBpfProgram mirrors C's struct bpf_program.
// Go's natural alignment inserts correct padding between Len and Insns
// on 64-bit (4 bytes padding) vs 32-bit (no padding).
type pcapBpfProgram struct {
	Len   uint32
	Insns *pcapBpfInstruction
}

type pcapStats struct {
	Recv   uint32
	Drop   uint32
	Ifdrop uint32
}

type pcapCint int32

// pcapIf mirrors C's struct pcap_if (pcap_if_t).
// Go's alignment rules produce the correct layout on both 32-bit and 64-bit.
type pcapIf struct {
	Next        *pcapIf
	Name        *byte
	Description *byte
	Addresses   *pcapAddr
	Flags       uint32
}

type pcapAddr struct {
	Next      *pcapAddr
	Addr      *syscall.RawSockaddr
	Netmask   *syscall.RawSockaddr
	Broadaddr *syscall.RawSockaddr
	Dstaddr   *syscall.RawSockaddr
}
