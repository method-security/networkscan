//go:build !linux && !darwin && !windows

package operatingsystem

import (
	"fmt"

	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
)

// GetArpEntries returns an explicit error on platforms that are not yet
// supported.
func GetArpEntries() ([]*discoverfern.ArpInterface, error) {
	return nil, fmt.Errorf("ARP table reading is not supported on this platform")
}
