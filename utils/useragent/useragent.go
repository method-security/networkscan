// Package useragent resolves the browser presets shared with WebProbe.
package useragent

import (
	common "github.com/Method-Security/networkscan/generated/go/common"
	pdua "github.com/projectdiscovery/useragent"
)

const fallback = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

// Resolve picks once per scan invocation; callers reuse the result across targets
// and requests rather than changing the client identity between probes.
func Resolve(preset common.UserAgentPreset) string {
	var filter pdua.Filter
	switch preset {
	case common.UserAgentPresetChrome:
		filter = func(ua *pdua.UserAgent) bool {
			return pdua.ContainsTagsAny(ua, "Chrome", "Chromium") && !pdua.ContainsTagsAny(ua, "Edge")
		}
	case common.UserAgentPresetFirefox:
		filter = pdua.Mozilla
	case common.UserAgentPresetSafari:
		filter = func(ua *pdua.UserAgent) bool {
			return pdua.ContainsTagsAny(ua, "Safari") && !pdua.ContainsTagsAny(ua, "Chrome", "Chromium", "Edge")
		}
	case common.UserAgentPresetEdge:
		filter = func(ua *pdua.UserAgent) bool { return pdua.ContainsTagsAny(ua, "Edge") }
	case common.UserAgentPresetCurl:
		return "curl/8.4.0"
	}
	if filter != nil {
		if uas, err := pdua.PickWithFilters(1, filter); err == nil && len(uas) > 0 {
			return uas[0].Raw
		}
	}
	if ua := pdua.PickRandom(); ua != nil {
		return ua.Raw
	}
	return fallback
}
