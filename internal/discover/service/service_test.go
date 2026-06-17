package service

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	fxplugins "github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

func TestFingerprintxRegisteredProtocolsMapToProtocolType(t *testing.T) {
	var pluginIDs []string
	seen := make(map[string]struct{})
	for _, protocolPlugins := range fxplugins.Plugins {
		for _, plugin := range protocolPlugins {
			id := fmt.Sprintf("%s/%s", plugin.Type().String(), plugin.Name())
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			pluginIDs = append(pluginIDs, id)
		}
	}
	sort.Strings(pluginIDs)

	if len(pluginIDs) == 0 {
		t.Fatal("no fingerprintx plugins registered")
	}
	for _, id := range pluginIDs {
		_, name, _ := strings.Cut(id, "/")
		if _, err := fxProtocolToProtocolType(name); err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
}
