package plugins

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/Method-Security/networkscan/configs"
)

// cipVendorsConfig mirrors the on-disk JSON layout under configs/discover/service/cip_vendors.json.
// Vendor IDs and device type codes are uint16 on the wire; the JSON keys are decimal strings.
type cipVendorsConfig struct {
	Vendors     map[string]string `json:"vendors"`
	DeviceTypes map[string]string `json:"device_types"`
}

var (
	cipVendorsConfigOnce sync.Once
	cipVendorNames       map[uint16]string
	cipDeviceTypeNames   map[uint16]string
	cipVendorsConfigErr  error
)

// loadCIPVendorsConfig reads the embedded JSON config once and populates the lookup maps.
// On parse failure the maps are left empty and the error is cached so callers
// degrade gracefully (numeric IDs are still returned even without name lookup).
func loadCIPVendorsConfig() {
	cipVendorsConfigOnce.Do(func() {
		data, err := configs.ReadFile("discover/service/cip_vendors.json")
		if err != nil {
			cipVendorsConfigErr = fmt.Errorf("failed to read cip_vendors config: %w", err)
			return
		}
		var cfg cipVendorsConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			cipVendorsConfigErr = fmt.Errorf("failed to parse cip_vendors config: %w", err)
			return
		}
		cipVendorNames = parseUint16KeyedMap(cfg.Vendors)
		cipDeviceTypeNames = parseUint16KeyedMap(cfg.DeviceTypes)
	})
}

// parseUint16KeyedMap converts a map[string]string with decimal-string keys
// into a map[uint16]string. Entries whose keys don't parse or overflow uint16
// are silently dropped (config is dev-controlled; nothing useful to do at runtime).
func parseUint16KeyedMap(src map[string]string) map[uint16]string {
	out := make(map[uint16]string, len(src))
	for k, v := range src {
		n, err := strconv.ParseUint(k, 10, 16)
		if err != nil {
			continue
		}
		out[uint16(n)] = v
	}
	return out
}

// cipVendorName returns the vendor name for a given vendor ID, or empty string if unknown.
func cipVendorName(vendorID uint16) string {
	loadCIPVendorsConfig()
	return cipVendorNames[vendorID]
}

// cipDeviceTypeName returns the device type name for a given device type code, or empty string if unknown.
func cipDeviceTypeName(deviceType uint16) string {
	loadCIPVendorsConfig()
	return cipDeviceTypeNames[deviceType]
}
