package utils

import (
	"fmt"
	"strings"

	pentest "github.com/Method-Security/networkscan/generated/go/common/pentest"
)

// ServiceActionParser defines the interface for parsing service-specific actions
type ServiceActionParser interface {
	ParseActions(actionStrings []string) ([]*pentest.PentestServiceAction, error)
	GetValidActions() []string
	ContainsAction(actions []*pentest.PentestServiceAction, target interface{}) bool
}

// SMBActionParser handles SMB-specific action parsing
type SMBActionParser struct{}

func (p *SMBActionParser) ParseActions(actionStrings []string) ([]*pentest.PentestServiceAction, error) {
	var actions []*pentest.PentestServiceAction

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
			smbAction, err := pentest.NewPentestSmbActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid SMB action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			action := pentest.NewPentestServiceActionFromSmb(smbAction)
			actions = append(actions, action)
		}
	}

	return actions, nil
}

func (p *SMBActionParser) GetValidActions() []string {
	return []string{"auth", "samdump", "lsadump"}
}

func (p *SMBActionParser) ContainsAction(actions []*pentest.PentestServiceAction, target interface{}) bool {
	targetAction, ok := target.(pentest.PentestSmbAction)
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

func (p *SSHActionParser) ParseActions(actionStrings []string) ([]*pentest.PentestServiceAction, error) {
	var actions []*pentest.PentestServiceAction

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
			sshAction, err := pentest.NewPentestSshActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid SSH action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			action := pentest.NewPentestServiceActionFromSsh(sshAction)
			actions = append(actions, action)
		}
	}

	return actions, nil
}

func (p *SSHActionParser) GetValidActions() []string {
	return []string{"auth", "command", "user_enum", "file_transfer"}
}

func (p *SSHActionParser) ContainsAction(actions []*pentest.PentestServiceAction, target interface{}) bool {
	targetAction, ok := target.(pentest.PentestSshAction)
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

func (p *TelnetActionParser) ParseActions(actionStrings []string) ([]*pentest.PentestServiceAction, error) {
	var actions []*pentest.PentestServiceAction

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
			telnetAction, err := pentest.NewPentestTelnetActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid Telnet action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			action := pentest.NewPentestServiceActionFromTelnet(telnetAction)
			actions = append(actions, action)
		}
	}

	return actions, nil
}

func (p *TelnetActionParser) GetValidActions() []string {
	return []string{"auth", "command"}
}

func (p *TelnetActionParser) ContainsAction(actions []*pentest.PentestServiceAction, target interface{}) bool {
	targetAction, ok := target.(pentest.PentestTelnetAction)
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
func (au *ActionUtil) ContainsAction(actions []*pentest.PentestServiceAction, serviceType string, target interface{}) bool {
	switch serviceType {
	case "smb":
		if targetAction, ok := target.(pentest.PentestSmbAction); ok {
			return GetSMBParser().ContainsAction(actions, targetAction)
		}
	case "ssh":
		if targetAction, ok := target.(pentest.PentestSshAction); ok {
			return GetSSHParser().ContainsAction(actions, targetAction)
		}
	case "telnet":
		if targetAction, ok := target.(pentest.PentestTelnetAction); ok {
			return GetTelnetParser().ContainsAction(actions, targetAction)
		}
	}
	return false
}

// Global parser instances (singletons)
var (
	smbParserInstance    *SMBActionParser
	sshParserInstance    *SSHActionParser
	telnetParserInstance *TelnetActionParser
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

// GetActionUtil returns the singleton action utility
func GetActionUtil() *ActionUtil {
	if actionUtilInstance == nil {
		actionUtilInstance = &ActionUtil{}
	}
	return actionUtilInstance
}
