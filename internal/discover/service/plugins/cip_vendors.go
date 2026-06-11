package plugins

// cipVendorNames maps CIP Vendor IDs to human-readable vendor names.
// Source: ODVA EtherNet/IP vendor ID registry (common entries).
var cipVendorNames = map[uint16]string{
	1:    "Rockwell Automation/Allen-Bradley",
	5:    "Schneider Automation (Square D / Modicon)",
	12:   "Schneider Electric / Modicon",
	26:   "Festo",
	40:   "WAGO",
	46:   "ABB",
	47:   "OMRON Corporation",
	50:   "Pepperl+Fuchs",
	90:   "Honeywell",
	96:   "Belden / Hirschmann",
	108:  "ProSoft Technology",
	256:  "Phoenix Contact",
	283:  "HMS Industrial Networks",
	318:  "Unitronics",
	504:  "Mitsubishi Electric",
	575:  "Bosch Rexroth",
	678:  "Yokogawa",
	691:  "Beckhoff",
	808:  "Murrelektronik",
	900:  "Festo Didactic",
	999:  "Stratus Technologies",
	1126: "B&R Industrial Automation",
	1454: "ifm electronic",
}

// cipDeviceTypeNames maps CIP Device Type codes to human-readable names.
var cipDeviceTypeNames = map[uint16]string{
	0x000C: "Communications Adapter",
	0x000E: "PLC",
	0x0028: "AC Drive",
	0x002B: "Generic Device",
}

// cipVendorName returns the vendor name for a given vendor ID, or empty string if unknown.
func cipVendorName(vendorID uint16) string {
	return cipVendorNames[vendorID]
}

// cipDeviceTypeName returns the device type name for a given device type code, or empty string if unknown.
func cipDeviceTypeName(deviceType uint16) string {
	return cipDeviceTypeNames[deviceType]
}
