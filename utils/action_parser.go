package utils

import (
	"fmt"
	"strings"

	ldapcommonfern "github.com/Method-Security/networkscan/generated/go/common/ldap"
	pentestcommonfern "github.com/Method-Security/networkscan/generated/go/common/pentest"
	smbcommonfern "github.com/Method-Security/networkscan/generated/go/common/smb"
	sshcommonfern "github.com/Method-Security/networkscan/generated/go/common/ssh"
	telnetcommonfern "github.com/Method-Security/networkscan/generated/go/common/telnet"
)

// ServiceActionParser defines the interface for parsing service-specific actions
type ServiceActionParser interface {
	ParseActions(actionStrings []string) ([]*pentestcommonfern.PentestServiceAction, error)
	GetValidActions() []string
	ContainsAction(actions []*pentestcommonfern.PentestServiceAction, target interface{}) bool
}

// SMBActionParser handles SMB-specific action parsing
type SMBActionParser struct{}

func (p *SMBActionParser) ParseActions(actionStrings []string) ([]*pentestcommonfern.PentestServiceAction, error) {
	var actions []*pentestcommonfern.PentestServiceAction

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
			smbAction, err := smbcommonfern.NewPentestSmbActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid SMB action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			action := pentestcommonfern.NewPentestServiceActionFromSmb(smbAction)
			actions = append(actions, action)
		}
	}

	return actions, nil
}

func (p *SMBActionParser) GetValidActions() []string {
	return []string{"auth", "samdump", "lsadump"}
}

func (p *SMBActionParser) ContainsAction(actions []*pentestcommonfern.PentestServiceAction, target interface{}) bool {
	targetAction, ok := target.(smbcommonfern.PentestSmbAction)
	if !ok {
		return false
	}
	for _, action := range actions {
		if action.GetType() == "smb" && action.GetSmb() == targetAction {
			return true
		}
	}
	return false
}

// SSHActionParser handles SSH-specific action parsing
type SSHActionParser struct{}

func (p *SSHActionParser) ParseActions(actionStrings []string) ([]*pentestcommonfern.PentestServiceAction, error) {
	var actions []*pentestcommonfern.PentestServiceAction

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
			sshAction, err := sshcommonfern.NewPentestSshActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid SSH action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			action := pentestcommonfern.NewPentestServiceActionFromSsh(sshAction)
			actions = append(actions, action)
		}
	}

	return actions, nil
}

func (p *SSHActionParser) GetValidActions() []string {
	return []string{"auth", "command", "user_enum", "file_transfer"}
}

func (p *SSHActionParser) ContainsAction(actions []*pentestcommonfern.PentestServiceAction, target interface{}) bool {
	targetAction, ok := target.(sshcommonfern.PentestSshAction)
	if !ok {
		return false
	}
	for _, action := range actions {
		if action.GetType() == "ssh" && action.GetSsh() == targetAction {
			return true
		}
	}
	return false
}

// TelnetActionParser handles Telnet-specific action parsing
type TelnetActionParser struct{}

func (p *TelnetActionParser) ParseActions(actionStrings []string) ([]*pentestcommonfern.PentestServiceAction, error) {
	var actions []*pentestcommonfern.PentestServiceAction

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
			telnetAction, err := telnetcommonfern.NewPentestTelnetActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid Telnet action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			action := pentestcommonfern.NewPentestServiceActionFromTelnet(telnetAction)
			actions = append(actions, action)
		}
	}

	return actions, nil
}

func (p *TelnetActionParser) GetValidActions() []string {
	return []string{"auth", "command"}
}

func (p *TelnetActionParser) ContainsAction(actions []*pentestcommonfern.PentestServiceAction, target interface{}) bool {
	targetAction, ok := target.(telnetcommonfern.PentestTelnetAction)
	if !ok {
		return false
	}
	for _, action := range actions {
		if action.GetType() == "telnet" && action.GetTelnet() == targetAction {
			return true
		}
	}
	return false
}

// ActionUtil provides generic utilities for working with actions
type ActionUtil struct{}

// ContainsAction checks if actions contain a specific target action (generic version)
func (au *ActionUtil) ContainsAction(actions []*pentestcommonfern.PentestServiceAction, serviceType string, target interface{}) bool {
	switch serviceType {
	case "smb":
		if targetAction, ok := target.(smbcommonfern.PentestSmbAction); ok {
			return GetSMBParser().ContainsAction(actions, targetAction)
		}
	case "ssh":
		if targetAction, ok := target.(sshcommonfern.PentestSshAction); ok {
			return GetSSHParser().ContainsAction(actions, targetAction)
		}
	case "telnet":
		if targetAction, ok := target.(telnetcommonfern.PentestTelnetAction); ok {
			return GetTelnetParser().ContainsAction(actions, targetAction)
		}
	}
	return false
}

// LDAPActionParser handles LDAP-specific action parsing
type LDAPActionParser struct{}

func (p *LDAPActionParser) ParseActions(actionStrings []string) ([]ldapcommonfern.LdapAction, error) {
	var actions []ldapcommonfern.LdapAction

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
			ldapAction, err := ldapcommonfern.NewLdapActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid LDAP action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			actions = append(actions, ldapAction)
		}
	}

	return actions, nil
}

func (p *LDAPActionParser) GetValidActions() []string {
	return []string{"auth", "domaindump"}
}

func (p *LDAPActionParser) ContainsAction(actions []ldapcommonfern.LdapAction, target ldapcommonfern.LdapAction) bool {
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
	actionUtilInstance   *ActionUtil
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

// GetActionUtil returns the singleton action utility
func GetActionUtil() *ActionUtil {
	if actionUtilInstance == nil {
		actionUtilInstance = &ActionUtil{}
	}
	return actionUtilInstance
}
