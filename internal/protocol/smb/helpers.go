package smb

import (
	"fmt"
	"regexp"
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

// parseInt safely converts string to int
func parseInt(s string) int {
	var result int
	_, _ = fmt.Sscanf(s, "%d", &result)
	return result
}
