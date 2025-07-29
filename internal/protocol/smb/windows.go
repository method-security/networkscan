package smb

import (
	"fmt"
	"regexp"
)

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

// WindowsBuildMapping maps Windows build numbers to human-readable versions
var WindowsBuildMapping = map[string]string{
	// Windows Server builds
	"20348": "Windows Server 2022",
	"19041": "Windows Server 2022 (Insider)",
	"17763": "Windows Server 2019",
	"14393": "Windows Server 2016",
	"10586": "Windows Server 2016 (Technical Preview)",
	"9600":  "Windows Server 2012 R2",
	"9200":  "Windows Server 2012",
	"7601":  "Windows Server 2008 R2 SP1 / Windows 7 SP1",
	"6002":  "Windows Server 2008 SP2 / Windows Vista SP2",
	"6001":  "Windows Server 2008 SP1 / Windows Vista SP1",
	"6000":  "Windows Server 2008 / Windows Vista",

	// Windows 11 builds
	"22631": "Windows 11 23H2",
	"22621": "Windows 11 22H2",
	"22000": "Windows 11 21H2",

	// Windows 10 builds
	"19045": "Windows 10 22H2",
	"19044": "Windows 10 21H2",
	"19043": "Windows 10 21H1",
	"19042": "Windows 10 20H2",
	"18363": "Windows 10 1909",
	"18362": "Windows 10 1903",
	"17134": "Windows 10 1803",
	"16299": "Windows 10 1709",
	"15063": "Windows 10 1703",
	"10240": "Windows 10 RTM",

	// Windows 8/8.1
	"9431": "Windows 8.1 Update 1",

	// Windows 7 (additional builds)
	"7600": "Windows 7 RTM",
}

// parseWindowsVersion extracts and enhances Windows version information
func parseWindowsVersion(rawOSVersion string) string {
	if rawOSVersion == "" {
		return "Windows Server"
	}

	// Extract build number using regex
	buildRegex := regexp.MustCompile(`Build (\d+)`)
	matches := buildRegex.FindStringSubmatch(rawOSVersion)

	if len(matches) > 1 {
		buildNumber := matches[1]

		// Look up human-readable version
		if readableVersion, exists := WindowsBuildMapping[buildNumber]; exists {
			return readableVersion
		}

		// If not found, try to classify by build number ranges
		return classifyWindowsByBuildNumber(buildNumber, rawOSVersion)
	}

	// Fallback to original version if no build number found
	return rawOSVersion
}

// classifyWindowsByBuildNumber classifies Windows versions by build number ranges
func classifyWindowsByBuildNumber(buildNumber, rawVersion string) string {
	build := parseInt(buildNumber)

	switch {
	case build >= 22000:
		return fmt.Sprintf("Windows 11 (Build %s)", buildNumber)
	case build >= 19000:
		return fmt.Sprintf("Windows 10/Server 2019-2022 (Build %s)", buildNumber)
	case build >= 17000:
		return fmt.Sprintf("Windows 10/Server 2016-2019 (Build %s)", buildNumber)
	case build >= 14000:
		return fmt.Sprintf("Windows 10/Server 2016 (Build %s)", buildNumber)
	case build >= 10000:
		return fmt.Sprintf("Windows 10 (Build %s)", buildNumber)
	case build >= 9000:
		return fmt.Sprintf("Windows 8/Server 2012 (Build %s)", buildNumber)
	case build >= 7000:
		return fmt.Sprintf("Windows 7/Server 2008 (Build %s)", buildNumber)
	case build >= 6000:
		return fmt.Sprintf("Windows Vista/Server 2008 (Build %s)", buildNumber)
	default:
		return rawVersion // Return original if can't classify
	}
}

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

// parseInt safely converts string to int
func parseInt(s string) int {
	var result int
	_, _ = fmt.Sscanf(s, "%d", &result)
	return result
}
