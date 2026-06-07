package utils

import (
	"fmt"
	"strings"

	ftpfern "github.com/Method-Security/networkscan/generated/go/pentest/ftp"
	ldapfern "github.com/Method-Security/networkscan/generated/go/pentest/ldap"
	msrpcfern "github.com/Method-Security/networkscan/generated/go/pentest/msrpc"
	redisfern "github.com/Method-Security/networkscan/generated/go/pentest/redis"
	smbfern "github.com/Method-Security/networkscan/generated/go/pentest/smb"
	sshfern "github.com/Method-Security/networkscan/generated/go/pentest/ssh"
	telnetfern "github.com/Method-Security/networkscan/generated/go/pentest/telnet"
	winrmfern "github.com/Method-Security/networkscan/generated/go/pentest/winrm"
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
	return []string{"PROBE", "AUTH", "SAMDUMP", "LSADUMP", "SHARES_MAP", "SHARE_DOWNLOAD", "EXEC"}
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
	return []string{"AUTH", "EXEC", "FILE_TRANSFER"}
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
	return []string{"AUTH", "EXEC"}
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

// MSRPCActionParser handles MSRPC-specific action parsing
type MSRPCActionParser struct{}

func (p *MSRPCActionParser) ParseActions(actionStrings []string) ([]msrpcfern.PentestMsrpcAction, error) {
	var actions []msrpcfern.PentestMsrpcAction

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
			msrpcAction, err := msrpcfern.NewPentestMsrpcActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid MSRPC action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			actions = append(actions, msrpcAction)
		}
	}

	return actions, nil
}

func (p *MSRPCActionParser) GetValidActions() []string {
	return []string{"DCSYNC"}
}

func (p *MSRPCActionParser) ContainsAction(actions []msrpcfern.PentestMsrpcAction, target msrpcfern.PentestMsrpcAction) bool {
	for _, action := range actions {
		if action == target {
			return true
		}
	}
	return false
}

// WinRMActionParser handles WinRM-specific action parsing
type WinRMActionParser struct{}

func (p *WinRMActionParser) ParseActions(actionStrings []string) ([]winrmfern.PentestWinrmAction, error) {
	var actions []winrmfern.PentestWinrmAction

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
			winrmAction, err := winrmfern.NewPentestWinrmActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid WinRM action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			actions = append(actions, winrmAction)
		}
	}

	return actions, nil
}

func (p *WinRMActionParser) GetValidActions() []string {
	return []string{"AUTH", "EXEC"}
}

func (p *WinRMActionParser) ContainsAction(actions []winrmfern.PentestWinrmAction, target winrmfern.PentestWinrmAction) bool {
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
	msrpcParserInstance  *MSRPCActionParser
	ftpParserInstance    *FTPActionParser
	winrmParserInstance  *WinRMActionParser
	redisParserInstance  *RedisActionParser
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

// GetMSRPCParser returns the singleton MSRPC action parser
func GetMSRPCParser() *MSRPCActionParser {
	if msrpcParserInstance == nil {
		msrpcParserInstance = &MSRPCActionParser{}
	}
	return msrpcParserInstance
}

// GetFTPParser returns the singleton FTP action parser
func GetFTPParser() *FTPActionParser {
	if ftpParserInstance == nil {
		ftpParserInstance = &FTPActionParser{}
	}
	return ftpParserInstance
}

// GetWinRMParser returns the singleton WinRM action parser
func GetWinRMParser() *WinRMActionParser {
	if winrmParserInstance == nil {
		winrmParserInstance = &WinRMActionParser{}
	}
	return winrmParserInstance
}

// FTPActionParser handles FTP-specific action parsing
type FTPActionParser struct{}

func (p *FTPActionParser) ParseActions(actionStrings []string) ([]ftpfern.PentestFtpAction, error) {
	var actions []ftpfern.PentestFtpAction

	for _, actionStr := range actionStrings {
		parts := strings.Split(actionStr, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			upperPart := strings.ToUpper(part)
			ftpAction, err := ftpfern.NewPentestFtpActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid FTP action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			actions = append(actions, ftpAction)
		}
	}

	return actions, nil
}

func (p *FTPActionParser) GetValidActions() []string {
	return []string{"LIST", "WRITE_TEST", "DOWNLOAD", "UPLOAD"}
}

func (p *FTPActionParser) ContainsAction(actions []ftpfern.PentestFtpAction, target ftpfern.PentestFtpAction) bool {
	for _, action := range actions {
		if action == target {
			return true
		}
	}
	return false
}

// RedisActionParser handles Redis-specific action parsing
type RedisActionParser struct{}

// GetRedisParser returns the singleton Redis action parser
func GetRedisParser() *RedisActionParser {
	if redisParserInstance == nil {
		redisParserInstance = &RedisActionParser{}
	}
	return redisParserInstance
}

func (p *RedisActionParser) ParseActions(actionStrings []string) ([]redisfern.PentestRedisAction, error) {
	var actions []redisfern.PentestRedisAction

	for _, actionStr := range actionStrings {
		parts := strings.Split(actionStr, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			upperPart := strings.ToUpper(part)
			redisAction, err := redisfern.NewPentestRedisActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid Redis action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			actions = append(actions, redisAction)
		}
	}

	return actions, nil
}

func (p *RedisActionParser) GetValidActions() []string {
	return []string{"AUTH"}
}

func (p *RedisActionParser) ContainsAction(actions []redisfern.PentestRedisAction, target redisfern.PentestRedisAction) bool {
	for _, action := range actions {
		if action == target {
			return true
		}
	}
	return false
}
