package ike

import (
	"encoding/json"
	"strings"

	"github.com/Method-Security/networkscan/configs"
)

type vendorIDEntry struct {
	HexPrefix string `json:"hexPrefix"`
	Vendor    string `json:"vendor"`
	Class     string `json:"class"`
}

type vendorIDDatabase struct {
	VendorIds []vendorIDEntry `json:"vendorIds"`
}

var loadedVendorDB vendorIDDatabase

func init() {
	data, err := configs.ReadFile("enumerate/ike/vendor_id_classes.json")
	if err != nil {
		// fallback to empty — non-fatal
		loadedVendorDB = vendorIDDatabase{}
		return
	}
	if err := json.Unmarshal(data, &loadedVendorDB); err != nil {
		// fallback to empty — non-fatal
		loadedVendorDB = vendorIDDatabase{}
	}
}

// lookupVendorClass returns the vendor class string for a hex-encoded vendor ID,
// or empty string if not found. Performs prefix matching on the lowercase hex.
func lookupVendorClass(hexVendorID string) string {
	lower := strings.ToLower(hexVendorID)
	for _, entry := range loadedVendorDB.VendorIds {
		prefix := strings.ToLower(entry.HexPrefix)
		if strings.HasPrefix(lower, prefix) {
			return entry.Class
		}
	}
	return ""
}

// lookupVendorName returns the human-readable vendor name for a hex-encoded vendor ID,
// or empty string if not found.
func lookupVendorName(hexVendorID string) string {
	lower := strings.ToLower(hexVendorID)
	for _, entry := range loadedVendorDB.VendorIds {
		prefix := strings.ToLower(entry.HexPrefix)
		if strings.HasPrefix(lower, prefix) {
			return entry.Vendor
		}
	}
	return ""
}
