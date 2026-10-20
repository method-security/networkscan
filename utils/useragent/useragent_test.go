package useragent

import (
	"strings"
	"testing"

	"github.com/Method-Security/networkscan/generated/go/common"
)

func TestResolve(t *testing.T) {
	for _, preset := range []common.UserAgentPreset{
		common.UserAgentPresetRandom, common.UserAgentPresetChrome, common.UserAgentPresetFirefox,
		common.UserAgentPresetSafari, common.UserAgentPresetEdge, common.UserAgentPresetCurl,
	} {
		t.Run(string(preset), func(t *testing.T) {
			for range 10 {
				ua := Resolve(preset)
				if ua == "" || strings.ContainsAny(ua, "\r\n") {
					t.Fatalf("invalid user agent: %q", ua)
				}
				switch preset {
				case common.UserAgentPresetChrome:
					if !strings.Contains(ua, "Chrome") && !strings.Contains(ua, "Chromium") {
						t.Fatalf("not Chrome: %q", ua)
					}
				case common.UserAgentPresetFirefox:
					if !strings.Contains(ua, "Firefox") {
						t.Fatalf("not Firefox: %q", ua)
					}
				case common.UserAgentPresetSafari:
					if !strings.Contains(ua, "Safari") || strings.Contains(ua, "Chrome") {
						t.Fatalf("not Safari: %q", ua)
					}
				case common.UserAgentPresetEdge:
					if !strings.Contains(ua, "Edg") {
						t.Fatalf("not Edge: %q", ua)
					}
				case common.UserAgentPresetCurl:
					if ua != "curl/8.4.0" {
						t.Fatalf("not curl: %q", ua)
					}
				}
			}
		})
	}
}
