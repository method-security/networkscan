//go:build windows

package operatingsystem

import (
	// Standard
	"fmt"
	"net"
	"unsafe"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"

	// golang.org/x/sys/windows provides NewLazySystemDLL for safe DLL loading
	// without preloading attacks.
	"golang.org/x/sys/windows"
)

var (
	modIPHLPAPI       = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpNetTable = modIPHLPAPI.NewProc("GetIpNetTable")
)

// mibIPNetRow mirrors the Windows MIB_IPNETROW structure from iphlpapi.h.
// Layout (all uint32/byte fields, no padding):
//
//	dwIndex       uint32   — adapter index
//	dwPhysAddrLen uint32   — length of physical address (bytes)
//	bPhysAddr     [8]byte  — physical (MAC) address
//	dwAddr        uint32   — IPv4 address (network byte order, i.e. raw in_addr bytes)
//	dwType        uint32   — entry type (see mibIPNetType* constants)
type mibIPNetRow struct {
	Index       uint32
	PhysAddrLen uint32
	PhysAddr    [8]byte
	Addr        uint32
	Type        uint32
}

// mibIPNetTable mirrors MIB_IPNETTABLE. The Table field is variable-length;
// rows beyond index 0 are accessed via unsafe pointer arithmetic.
type mibIPNetTable struct {
	NumEntries uint32
	Table      [1]mibIPNetRow
}

const (
	mibIPNetTypeOther   uint32 = 1
	mibIPNetTypeInvalid uint32 = 2
	mibIPNetTypeDynamic uint32 = 3 // learned via ARP
	mibIPNetTypeStatic  uint32 = 4 // manually added

	errInsufficientBuffer uintptr = 122
	errNoData             uintptr = 232
)

// GetArpEntries reads the IPv4 ARP table on Windows using GetIpNetTable from
// iphlpapi.dll. No external processes are spawned; the call goes directly
// to the Windows IP Helper API.
func GetArpEntries() ([]*discoverfern.ArpInterface, error) {
	// First call with a nil buffer to obtain the required buffer size.
	var size uint32
	ret, _, _ := procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if ret != errInsufficientBuffer {
		if ret == errNoData {
			return nil, nil // ARP table is empty
		}
		if ret != 0 {
			return nil, fmt.Errorf("GetIpNetTable (size query) error: %d", ret)
		}
	}

	// Second call with a properly-sized buffer.
	buf := make([]byte, size)
	ret, _, _ = procGetIpNetTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0, // bOrder = FALSE (unsorted)
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetIpNetTable error: %d", ret)
	}

	table := (*mibIPNetTable)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibIPNetRow{})
	basePtr := uintptr(unsafe.Pointer(&table.Table[0]))

	ifaceMap := map[string][]*discoverfern.ArpEntry{}
	for i := uint32(0); i < table.NumEntries; i++ {
		row := (*mibIPNetRow)(unsafe.Pointer(basePtr + uintptr(i)*rowSize))

		// Skip entries that carry no useful mapping.
		if row.Type == mibIPNetTypeInvalid || row.Type == mibIPNetTypeOther {
			continue
		}
		if row.PhysAddrLen == 0 || row.PhysAddrLen > 8 {
			continue
		}

		// dwAddr is stored as a raw in_addr (network byte order). On a
		// little-endian CPU, reading it as uint32 reverses the byte order, so
		// we extract the octets LSB-first to recover the original bytes.
		ip := net.IP{
			byte(row.Addr),
			byte(row.Addr >> 8),
			byte(row.Addr >> 16),
			byte(row.Addr >> 24),
		}.String()

		mac := net.HardwareAddr(row.PhysAddr[:row.PhysAddrLen]).String()

		// Resolve adapter index to a friendly interface name; fall back to the
		// numeric index string if the lookup fails.
		ifaceName := fmt.Sprintf("%d", row.Index)
		if iface, err := net.InterfaceByIndex(int(row.Index)); err == nil {
			ifaceName = iface.Name
		}

		ifaceMap[ifaceName] = append(ifaceMap[ifaceName], &discoverfern.ArpEntry{
			Ip:  ip,
			Mac: mac,
		})
	}

	var interfaces []*discoverfern.ArpInterface
	for name, entries := range ifaceMap {
		interfaces = append(interfaces, &discoverfern.ArpInterface{
			Interface: name,
			Entries:   entries,
		})
	}

	return interfaces, nil
}
