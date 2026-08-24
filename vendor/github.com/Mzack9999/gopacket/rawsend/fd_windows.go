//go:build windows

package rawsend

import "syscall"

type sysSocketFD = syscall.Handle
