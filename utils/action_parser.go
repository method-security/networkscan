package utils

import (
	"fmt"
	"strings"

	ldapfern "github.com/Method-Security/networkscan/generated/go/pentest/ldap"
	smbfern "github.com/Method-Security/networkscan/generated/go/pentest/smb"
	sshfern "github.com/Method-Security/networkscan/generated/go/pentest/ssh"
	telnetfern "github.com/Method-Security/networkscan/generated/go/pentest/telnet"
)

// SMBActionParser handles SMB-specific action parsing
type SMBActionParser struct{}

func (p *SMBActionParser) ParseActions(actionStrings []string) ([]smbfern.PentestSmbAction, error) {
	var actions []smbfern.PentestSmbAction

	for _, actionStr := range actionStrings {
		// Handle comma-separated actions in a single flag
		parts := strings.Split(actionStr, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue // Skip empty parts
			}
			// Convert to uppercase for enum matching
			upperPart := strings.ToUpper(part)
			smbAction, err := smbfern.NewPentestSmbActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid SMB action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			actions = append(actions, smbAction)
		}
	}

	return actions, nil
}

func (p *SMBActionParser) GetValidActions() []string {
	return []string{"PROBE", "AUTH", "SAMDUMP", "LSADUMP", "SHARES"}
}

func (p *SMBActionParser) ContainsAction(actions []smbfern.PentestSmbAction, target smbfern.PentestSmbAction) bool {
	for _, action := range actions {
		if action == target {
			return true
		}
	}
	return false
}

// SSHActionParser handles SSH-specific action parsing
type SSHActionParser struct{}

func (p *SSHActionParser) ParseActions(actionStrings []string) ([]sshfern.PentestSshAction, error) {
	var actions []sshfern.PentestSshAction

	for _, actionStr := range actionStrings {
		// Handle comma-separated actions in a single flag
		parts := strings.Split(actionStr, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue // Skip empty parts
			}
			// Convert to uppercase for enum matching
			upperPart := strings.ToUpper(part)
			sshAction, err := sshfern.NewPentestSshActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid SSH action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			actions = append(actions, sshAction)
		}
	}

	return actions, nil
}

func (p *SSHActionParser) GetValidActions() []string {
	return []string{"AUTH", "COMMAND", "FILE_TRANSFER"}
}

func (p *SSHActionParser) ContainsAction(actions []sshfern.PentestSshAction, target sshfern.PentestSshAction) bool {
	for _, action := range actions {
		if action == target {
			return true
		}
	}
	return false
}

// TelnetActionParser handles Telnet-specific action parsing
type TelnetActionParser struct{}

func (p *TelnetActionParser) ParseActions(actionStrings []string) ([]telnetfern.PentestTelnetAction, error) {
	var actions []telnetfern.PentestTelnetAction

	for _, actionStr := range actionStrings {
		// Handle comma-separated actions in a single flag
		parts := strings.Split(actionStr, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue // Skip empty parts
			}
			// Convert to uppercase for enum matching
			upperPart := strings.ToUpper(part)
			telnetAction, err := telnetfern.NewPentestTelnetActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid Telnet action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			actions = append(actions, telnetAction)
		}
	}

	return actions, nil
}

func (p *TelnetActionParser) GetValidActions() []string {
	return []string{"AUTH"}
}

func (p *TelnetActionParser) ContainsAction(actions []telnetfern.PentestTelnetAction, target telnetfern.PentestTelnetAction) bool {
	for _, action := range actions {
		if action == target {
			return true
		}
	}
	return false
}

// LDAPActionParser handles LDAP-specific action parsing
type LDAPActionParser struct{}

func (p *LDAPActionParser) ParseActions(actionStrings []string) ([]ldapfern.PentestLdapAction, error) {
	var actions []ldapfern.PentestLdapAction

	for _, actionStr := range actionStrings {
		// Handle comma-separated actions in a single flag
		parts := strings.Split(actionStr, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue // Skip empty parts
			}
			// Convert to uppercase for enum matching
			upperPart := strings.ToUpper(part)
			ldapAction, err := ldapfern.NewPentestLdapActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid LDAP action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			actions = append(actions, ldapAction)
		}
	}

	return actions, nil
}

func (p *LDAPActionParser) GetValidActions() []string {
	return []string{"PROBE", "AUTH", "DOMAINDUMP"}
}

func (p *LDAPActionParser) ContainsAction(actions []ldapfern.PentestLdapAction, target ldapfern.PentestLdapAction) bool {
	for _, action := range actions {
		if action == target {
			return true
		}
	}
	return false
}

// Global parser instances (singletons)
var (
	smbParserInstance    *SMBActionParser
	sshParserInstance    *SSHActionParser
	telnetParserInstance *TelnetActionParser
	ldapParserInstance   *LDAPActionParser
)

// GetSMBParser returns the singleton SMB action parser
func GetSMBParser() *SMBActionParser {
	if smbParserInstance == nil {
		smbParserInstance = &SMBActionParser{}
	}
	return smbParserInstance
}

// GetSSHParser returns the singleton SSH action parser
func GetSSHParser() *SSHActionParser {
	if sshParserInstance == nil {
		sshParserInstance = &SSHActionParser{}
	}
	return sshParserInstance
}

// GetTelnetParser returns the singleton Telnet action parser
func GetTelnetParser() *TelnetActionParser {
	if telnetParserInstance == nil {
		telnetParserInstance = &TelnetActionParser{}
	}
	return telnetParserInstance
}

// GetLDAPParser returns the singleton LDAP action parser
func GetLDAPParser() *LDAPActionParser {
	if ldapParserInstance == nil {
		ldapParserInstance = &LDAPActionParser{}
	}
	return ldapParserInstance
}
