package smb

// Windows OS version constants (byte values for crypto operations)
const (
	WinUnknown      byte = 0x00
	WinXP           byte = 0x05
	WinVista        byte = 0x06
	Win7            byte = 0x07
	Win8            byte = 0x08
	Win81           byte = 0x09
	Win10           byte = 0x0A
	Win11           byte = 0x0B
	WinServer2003   byte = 0x10
	WinServer2008   byte = 0x11
	WinServer2008R2 byte = 0x12
	WinServer2012   byte = 0x13
	WinServer2012R2 byte = 0x14
	WinServer2016   byte = 0x15
	WinServer2019   byte = 0x16
	WinServer2022   byte = 0x17
)

// GetOSVersion determines Windows OS version byte constant from build and version info
func GetOSVersion(currentBuild int, currentVersion float64, server bool) byte {
	if server {
		switch {
		case currentBuild >= 20348:
			return WinServer2022
		case currentBuild >= 17763:
			return WinServer2019
		case currentBuild >= 14393:
			return WinServer2016
		case currentBuild >= 9600:
			return WinServer2012R2
		case currentBuild >= 9200:
			return WinServer2012
		case currentBuild >= 7601:
			return WinServer2008R2
		case currentBuild >= 6001:
			return WinServer2008
		case currentBuild >= 3790:
			return WinServer2003
		default:
			return WinUnknown
		}
	} else {
		switch {
		case currentVersion >= 10.0 && currentBuild >= 22000:
			return Win11
		case currentVersion >= 10.0:
			return Win10
		case currentVersion >= 6.3:
			return Win81
		case currentVersion >= 6.2:
			return Win8
		case currentVersion >= 6.1:
			return Win7
		case currentVersion >= 6.0:
			return WinVista
		case currentVersion >= 5.1:
			return WinXP
		default:
			return WinUnknown
		}
	}
}

// IsWin10After1607 checks if Windows version is Windows 10 Anniversary Update or later
func IsWin10After1607(build int, version float64) (bool, error) {
	return build >= 14393, nil
}
