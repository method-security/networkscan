package smb

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/msrrp"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	gosmb "github.com/jfjallid/go-smb/smb"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// Minimal SVCCTL (MS-SCMR) client for starting the Remote Registry service.
// Only implements the operations needed to start/query a service.

const (
	svcctlPipe    = "svcctl"
	svcctlUUID    = "367ABB81-9844-35F1-AD32-98F038001003"
	svcctlMajor   = uint16(2)
	svcctlMinor   = uint16(0)
	svcHandleSize = 20

	// Opcodes
	opCloseServiceHandle   = 0
	opQueryServiceStatus   = 6
	opChangeServiceConfigW = 11
	opOpenSCManagerW       = 15
	opOpenServiceW         = 16
	opStartServiceW        = 19

	// Service states
	svcStopped = 1
	svcRunning = 4

	// Start types
	svcStartDemand   = 3          // SERVICE_DEMAND_START (manual)
	svcStartDisabled = 4          // SERVICE_START_DISABLED
	svcNoChange      = 0xFFFFFFFF // SERVICE_NO_CHANGE

	// Error codes
	errServiceDisabled       = 0x00000422
	errServiceAlreadyRunning = 0x00000420

	// Access masks
	scManagerConnect = 0x0001
	svcQueryStatus   = 0x0004
	svcChangeConfig  = 0x0002
	svcQueryConfig   = 0x0001
	svcStart         = 0x0010
	svcStop          = 0x0020
)

// EnsureRemoteRegistryStarted connects to the SVCCTL service and starts
// the RemoteRegistry service if it's not already running. Returns true
// if the service was started by us (and should be stopped on cleanup).
func EnsureRemoteRegistryStarted(ctx context.Context, session *gosmb.Connection) (startedByUs bool, err error) {
	log := svc1log.FromContext(ctx)

	f, err := session.OpenFile("IPC$", svcctlPipe)
	if err != nil {
		return false, fmt.Errorf("failed to open svcctl pipe: %v", err)
	}
	defer func() { _ = f.CloseFile() }()

	transport, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		return false, fmt.Errorf("failed to create SVCCTL transport: %v", err)
	}

	bind, err := dcerpc.Bind(transport, svcctlUUID, svcctlMajor, svcctlMinor, msrrp.NDRUuid)
	if err != nil {
		return false, fmt.Errorf("failed to bind to SVCCTL: %v", err)
	}

	// Open SCM
	scHandle, err := svcctlOpenSCManager(bind)
	if err != nil {
		return false, fmt.Errorf("OpenSCManagerW failed: %v", err)
	}
	defer svcctlCloseHandle(bind, scHandle)

	// Open RemoteRegistry service
	svcHandle, err := svcctlOpenService(bind, scHandle, "RemoteRegistry")
	if err != nil {
		return false, fmt.Errorf("OpenServiceW(RemoteRegistry) failed: %v", err)
	}
	defer svcctlCloseHandle(bind, svcHandle)

	// Check current status
	state, err := svcctlQueryStatus(bind, svcHandle)
	if err != nil {
		return false, fmt.Errorf("QueryServiceStatus failed: %v", err)
	}

	if state == svcRunning {
		log.Info("Remote Registry service is already running")
		return false, nil
	}

	log.Info("Starting Remote Registry service")
	err = svcctlStartService(bind, svcHandle)
	if err != nil {
		// If service is disabled, change startup type to manual and retry
		if isServiceDisabledError(err) {
			log.Info("Remote Registry service is disabled, changing to manual start type")
			changeErr := svcctlChangeStartType(bind, svcHandle, svcStartDemand)
			if changeErr != nil {
				return false, fmt.Errorf("failed to change service start type: %v", changeErr)
			}
			err = svcctlStartService(bind, svcHandle)
			if err != nil {
				return false, fmt.Errorf("StartServiceW failed after enabling: %v", err)
			}
		} else {
			return false, fmt.Errorf("StartServiceW failed: %v", err)
		}
	}

	// Wait for service to start
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		state, err = svcctlQueryStatus(bind, svcHandle)
		if err != nil {
			return false, err
		}
		if state == svcRunning {
			log.Info("Remote Registry service started successfully")
			return true, nil
		}
	}

	return false, fmt.Errorf("Remote Registry service did not start within 10 seconds")
}

// --- NDR-encoded SVCCTL RPC calls ---

func svcctlOpenSCManager(bind *dcerpc.ServiceBind) ([]byte, error) {
	// OpenSCManagerW request:
	//   lpMachineName: NDR pointer to empty Unicode string
	//   lpDatabaseName: NULL pointer
	//   dwDesiredAccess: SC_MANAGER_CONNECT
	var req []byte

	// lpMachineName - pointer to Unicode null string
	req = appendNDRUnicodePtr(req, "\x00")
	// lpDatabaseName - NULL pointer
	req = appendUint32(req, 0)
	// dwDesiredAccess
	req = appendUint32(req, scManagerConnect)

	resp, err := bind.MakeRequest(opOpenSCManagerW, req)
	if err != nil {
		return nil, err
	}

	if len(resp) < svcHandleSize+4 {
		return nil, fmt.Errorf("OpenSCManagerW response too short: %d", len(resp))
	}

	retCode := binary.LittleEndian.Uint32(resp[svcHandleSize:])
	if retCode != 0 {
		return nil, fmt.Errorf("OpenSCManagerW returned error: 0x%08x", retCode)
	}

	handle := make([]byte, svcHandleSize)
	copy(handle, resp[:svcHandleSize])
	return handle, nil
}

func svcctlOpenService(bind *dcerpc.ServiceBind, scHandle []byte, serviceName string) ([]byte, error) {
	// OpenServiceW request:
	//   hSCManager: 20-byte context handle
	//   lpServiceName: NDR Unicode string
	//   dwDesiredAccess: SERVICE_QUERY_STATUS | SERVICE_START
	var req []byte

	req = append(req, scHandle...)
	req = appendNDRUnicode(req, serviceName)
	req = appendUint32(req, svcQueryStatus|svcQueryConfig|svcChangeConfig|svcStart|svcStop)

	resp, err := bind.MakeRequest(opOpenServiceW, req)
	if err != nil {
		return nil, err
	}

	if len(resp) < svcHandleSize+4 {
		return nil, fmt.Errorf("OpenServiceW response too short: %d", len(resp))
	}

	retCode := binary.LittleEndian.Uint32(resp[svcHandleSize:])
	if retCode != 0 {
		return nil, fmt.Errorf("OpenServiceW returned error: 0x%08x", retCode)
	}

	handle := make([]byte, svcHandleSize)
	copy(handle, resp[:svcHandleSize])
	return handle, nil
}

func svcctlQueryStatus(bind *dcerpc.ServiceBind, svcHandle []byte) (uint32, error) {
	resp, err := bind.MakeRequest(opQueryServiceStatus, svcHandle)
	if err != nil {
		return 0, err
	}

	// SERVICE_STATUS structure: 7 DWORDs = 28 bytes + return code
	if len(resp) < 32 {
		return 0, fmt.Errorf("QueryServiceStatus response too short: %d", len(resp))
	}

	retCode := binary.LittleEndian.Uint32(resp[28:])
	if retCode != 0 {
		return 0, fmt.Errorf("QueryServiceStatus returned error: 0x%08x", retCode)
	}

	// dwCurrentState is at offset 4 in SERVICE_STATUS
	state := binary.LittleEndian.Uint32(resp[4:8])
	return state, nil
}

func svcctlStartService(bind *dcerpc.ServiceBind, svcHandle []byte) error {
	// StartServiceW: handle + argc(0) + argv(NULL)
	var req []byte
	req = append(req, svcHandle...)
	req = appendUint32(req, 0) // argc
	req = appendUint32(req, 0) // argv = NULL

	resp, err := bind.MakeRequest(opStartServiceW, req)
	if err != nil {
		return err
	}

	if len(resp) < 4 {
		return fmt.Errorf("StartServiceW response too short")
	}

	retCode := binary.LittleEndian.Uint32(resp[:4])
	if retCode != 0 {
		if retCode == errServiceAlreadyRunning {
			return nil
		}
		return fmt.Errorf("StartServiceW returned error: 0x%08x", retCode)
	}
	return nil
}

func svcctlChangeStartType(bind *dcerpc.ServiceBind, svcHandle []byte, startType uint32) error {
	// ChangeServiceConfigW (opcode 11)
	// All fields set to SERVICE_NO_CHANGE except dwStartType
	var req []byte
	req = append(req, svcHandle...)
	req = appendUint32(req, svcNoChange) // dwServiceType
	req = appendUint32(req, startType)   // dwStartType
	req = appendUint32(req, svcNoChange) // dwErrorControl
	req = appendUint32(req, 0)           // lpBinaryPathName = NULL
	req = appendUint32(req, 0)           // lpLoadOrderGroup = NULL
	req = appendUint32(req, 0)           // lpdwTagId = NULL
	req = appendUint32(req, 0)           // lpDependencies = NULL
	req = appendUint32(req, 0)           // dwDependSize = 0
	req = appendUint32(req, 0)           // lpServiceStartName = NULL
	req = appendUint32(req, 0)           // lpPassword = NULL
	req = appendUint32(req, 0)           // dwPwSize = 0
	req = appendUint32(req, 0)           // lpDisplayName = NULL

	resp, err := bind.MakeRequest(opChangeServiceConfigW, req)
	if err != nil {
		return err
	}

	if len(resp) < 8 {
		return fmt.Errorf("ChangeServiceConfigW response too short: %d", len(resp))
	}

	// Response: lpdwTagId (4 bytes) + ReturnValue (4 bytes)
	retCode := binary.LittleEndian.Uint32(resp[4:8])
	if retCode != 0 {
		return fmt.Errorf("ChangeServiceConfigW returned error: 0x%08x", retCode)
	}
	return nil
}

func isServiceDisabledError(err error) bool {
	return err != nil && fmt.Sprintf("%v", err) == fmt.Sprintf("StartServiceW returned error: 0x%08x", errServiceDisabled)
}

func svcctlCloseHandle(bind *dcerpc.ServiceBind, handle []byte) {
	_, _ = bind.MakeRequest(opCloseServiceHandle, handle)
}

// --- NDR encoding helpers ---

func appendUint32(buf []byte, v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return append(buf, b...)
}

// appendNDRUnicodePtr encodes a unique pointer to an NDR-conformant Unicode string.
func appendNDRUnicodePtr(buf []byte, s string) []byte {
	// Referent ID (non-zero = valid pointer)
	buf = appendUint32(buf, 0x00020000)
	return appendNDRUnicode(buf, s)
}

// appendNDRUnicode encodes an NDR conformant-varying Unicode string (no pointer header).
func appendNDRUnicode(buf []byte, s string) []byte {
	runes := []rune(s)
	// Include null terminator
	u16 := utf16.Encode(append(runes, 0))
	count := uint32(len(u16))

	// Max count
	buf = appendUint32(buf, count)
	// Offset
	buf = appendUint32(buf, 0)
	// Actual count
	buf = appendUint32(buf, count)
	// UTF-16LE data
	for _, c := range u16 {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, c)
		buf = append(buf, b...)
	}
	// Pad to 4-byte boundary
	if len(u16)*2%4 != 0 {
		buf = append(buf, make([]byte, 4-len(u16)*2%4)...)
	}
	return buf
}
