// Package snmp implements SNMP authentication testing using the GoSNMP library.
package snmp

import (
	"context"
	"fmt"
	"net"
	"strconv"

	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	snmpfern "github.com/Method-Security/networkscan/generated/go/enumerate/snmp"
	snmplib "github.com/Method-Security/networkscan/internal/protocol/snmp"
)

// LibraryEnumerateSNMP implements NetworkApplicationLibrary for SNMP enumeration.
type LibraryEnumerateSNMP struct{}

// EnumerateTarget tests SNMP authentication posture:
// 1. Parse host and port from target string
// 2. Try SNMPv3 engine discovery to confirm v3 is present
// 3. Test if NoAuthNoPriv grants actual read access with common usernames
// 4. Report the required security level and which usernames work unauthenticated
func (s *LibraryEnumerateSNMP) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	var details snmpfern.EnumerateSnmpDetails
	details.Target = &target
	errors := []string{}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid target format %q: %v", target, err))
		return &enumeratefern.EnumerateServiceDetails{EnumerateSnmpDetails: &details}, errors
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid port %q: %v", portStr, err))
		return &enumeratefern.EnumerateServiceDetails{EnumerateSnmpDetails: &details}, errors
	}
	if port < 1 || port > 65535 {
		errors = append(errors, fmt.Sprintf("port %d out of range (1-65535)", port))
		return &enumeratefern.EnumerateServiceDetails{EnumerateSnmpDetails: &details}, errors
	}
	snmpPort := uint16(port)

	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			errors = append(errors, fmt.Sprintf("cannot resolve host %q: %v", host, err))
			return &enumeratefern.EnumerateServiceDetails{EnumerateSnmpDetails: &details}, errors
		}
		ip = ips[0]
	}

	// SNMPv3 engine discovery — needed to confirm v3 is present before auth testing
	v3Info, _, v3Err := snmplib.TrySNMPv3Discovery(ip, snmpPort, 2)
	v3Detected := v3Info != nil
	details.V3Detected = &v3Detected

	if !v3Detected {
		if v3Err != nil {
			errors = append(errors, fmt.Sprintf("SNMPv3 not detected: %v", v3Err))
		} else {
			errors = append(errors, "SNMPv3 not detected on target")
		}
		return &enumeratefern.EnumerateServiceDetails{EnumerateSnmpDetails: &details}, errors
	}

	// Test if NoAuthNoPriv grants actual read access with common usernames
	var workingUsernames []string
	for _, username := range snmplib.CommonNoAuthUsernames {
		if ok, _ := snmplib.TrySNMPv3NoAuthGet(ip, snmpPort, username); ok {
			workingUsernames = append(workingUsernames, username)
		}
	}

	noAuthAccess := len(workingUsernames) > 0
	details.V3NoAuthAccess = &noAuthAccess
	if noAuthAccess {
		details.V3UnauthenticatedUsernames = workingUsernames
		level := "noAuthNoPriv"
		details.V3RequiredSecurityLevel = &level
	} else {
		level := "authNoPriv"
		details.V3RequiredSecurityLevel = &level
	}

	return &enumeratefern.EnumerateServiceDetails{EnumerateSnmpDetails: &details}, errors
}
