package utils

import (
	"fmt"
	"strings"

	ftpfern "github.com/Method-Security/networkscan/generated/go/pentest/ftp"
	imapfern "github.com/Method-Security/networkscan/generated/go/pentest/imap"
	ldapfern "github.com/Method-Security/networkscan/generated/go/pentest/ldap"
	mongodbfern "github.com/Method-Security/networkscan/generated/go/pentest/mongodb"
	msrpcfern "github.com/Method-Security/networkscan/generated/go/pentest/msrpc"
	mssqlfern "github.com/Method-Security/networkscan/generated/go/pentest/mssql"
	mysqlfern "github.com/Method-Security/networkscan/generated/go/pentest/mysql"
	postgresfern "github.com/Method-Security/networkscan/generated/go/pentest/postgres"
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

// MongoDBActionParser handles MongoDB-specific action parsing
type MongoDBActionParser struct{}

func (p *MongoDBActionParser) ParseActions(actionStrings []string) ([]mongodbfern.PentestMongodbAction, error) {
	var actions []mongodbfern.PentestMongodbAction

	for _, actionStr := range actionStrings {
		parts := strings.Split(actionStr, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			upperPart := strings.ToUpper(part)
			mongodbAction, err := mongodbfern.NewPentestMongodbActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid MongoDB action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			actions = append(actions, mongodbAction)
		}
	}

	return actions, nil
}

func (p *MongoDBActionParser) GetValidActions() []string {
	return []string{"PROBE", "AUTH", "QUERY"}
}

func (p *MongoDBActionParser) ContainsAction(actions []mongodbfern.PentestMongodbAction, target mongodbfern.PentestMongodbAction) bool {
	for _, action := range actions {
		if action == target {
			return true
		}
	}
	return false
}

// Global parser instances (singletons)
var (
	smbParserInstance      *SMBActionParser
	sshParserInstance      *SSHActionParser
	telnetParserInstance   *TelnetActionParser
	ldapParserInstance     *LDAPActionParser
	msrpcParserInstance    *MSRPCActionParser
	ftpParserInstance      *FTPActionParser
	winrmParserInstance    *WinRMActionParser
	mongodbParserInstance  *MongoDBActionParser
	redisParserInstance    *RedisActionParser
	imapParserInstance     *IMAPActionParser
	mssqlParserInstance    *MSSQLActionParser
	mysqlParserInstance    *MySQLActionParser
	postgresParserInstance *PostgresActionParser
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

// GetMongoDBParser returns the singleton MongoDB action parser
func GetMongoDBParser() *MongoDBActionParser {
	if mongodbParserInstance == nil {
		mongodbParserInstance = &MongoDBActionParser{}
	}
	return mongodbParserInstance
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

// MySQLActionParser handles MySQL-specific action parsing
type MySQLActionParser struct{}

// GetMySQLParser returns the singleton MySQL action parser
func GetMySQLParser() *MySQLActionParser {
	if mysqlParserInstance == nil {
		mysqlParserInstance = &MySQLActionParser{}
	}
	return mysqlParserInstance
}

func (p *MySQLActionParser) ParseActions(actionStrings []string) ([]mysqlfern.PentestMysqlAction, error) {
	var actions []mysqlfern.PentestMysqlAction

	for _, actionStr := range actionStrings {
		parts := strings.Split(actionStr, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			upperPart := strings.ToUpper(part)
			mysqlAction, err := mysqlfern.NewPentestMysqlActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid MySQL action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			actions = append(actions, mysqlAction)
		}
	}

	return actions, nil
}

func (p *MySQLActionParser) GetValidActions() []string {
	return []string{"PROBE", "AUTH"}
}

func (p *MySQLActionParser) ContainsAction(actions []mysqlfern.PentestMysqlAction, target mysqlfern.PentestMysqlAction) bool {
	for _, action := range actions {
		if action == target {
			return true
		}
	}
	return false
}

// IMAPActionParser handles IMAP-specific action parsing for the pentest
// service imap command (Mode B: AUTH + LIST_FOLDERS + FETCH_HEADERS + SEARCH).
type IMAPActionParser struct{}

// GetIMAPParser returns the singleton IMAP action parser.
func GetIMAPParser() *IMAPActionParser {
	if imapParserInstance == nil {
		imapParserInstance = &IMAPActionParser{}
	}
	return imapParserInstance
}

func (p *IMAPActionParser) ParseActions(actionStrings []string) ([]imapfern.PentestImapAction, error) {
	var actions []imapfern.PentestImapAction

	for _, actionStr := range actionStrings {
		parts := strings.Split(actionStr, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			upperPart := strings.ToUpper(part)
			imapAction, err := imapfern.NewPentestImapActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid IMAP action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			actions = append(actions, imapAction)
		}
	}

	return actions, nil
}

func (p *IMAPActionParser) GetValidActions() []string {
	return []string{"AUTH", "LIST_FOLDERS", "FETCH_HEADERS", "SEARCH"}
}

func (p *IMAPActionParser) ContainsAction(actions []imapfern.PentestImapAction, target imapfern.PentestImapAction) bool {
	for _, action := range actions {
		if action == target {
			return true
		}
	}
	return false
}

// MSSQLActionParser handles MSSQL-specific action parsing
type MSSQLActionParser struct{}

// GetMSSQLParser returns the singleton MSSQL action parser
func GetMSSQLParser() *MSSQLActionParser {
	if mssqlParserInstance == nil {
		mssqlParserInstance = &MSSQLActionParser{}
	}
	return mssqlParserInstance
}

func (p *MSSQLActionParser) ParseActions(actionStrings []string) ([]mssqlfern.PentestMssqlAction, error) {
	var actions []mssqlfern.PentestMssqlAction

	for _, actionStr := range actionStrings {
		parts := strings.Split(actionStr, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			upperPart := strings.ToUpper(part)
			mssqlAction, err := mssqlfern.NewPentestMssqlActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid MSSQL action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			actions = append(actions, mssqlAction)
		}
	}

	return actions, nil
}

func (p *MSSQLActionParser) GetValidActions() []string {
	return []string{"PROBE", "AUTH", "QUERY"}
}

func (p *MSSQLActionParser) ContainsAction(actions []mssqlfern.PentestMssqlAction, target mssqlfern.PentestMssqlAction) bool {
	for _, action := range actions {
		if action == target {
			return true
		}
	}
	return false
}

// PostgresActionParser handles Postgres-specific action parsing
type PostgresActionParser struct{}

// GetPostgresParser returns the singleton Postgres action parser
func GetPostgresParser() *PostgresActionParser {
	if postgresParserInstance == nil {
		postgresParserInstance = &PostgresActionParser{}
	}
	return postgresParserInstance
}

func (p *PostgresActionParser) ParseActions(actionStrings []string) ([]postgresfern.PentestPostgresAction, error) {
	var actions []postgresfern.PentestPostgresAction

	for _, actionStr := range actionStrings {
		parts := strings.Split(actionStr, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			upperPart := strings.ToUpper(part)
			postgresAction, err := postgresfern.NewPentestPostgresActionFromString(upperPart)
			if err != nil {
				return nil, fmt.Errorf("invalid Postgres action '%s': valid actions are %s", part, strings.Join(p.GetValidActions(), ","))
			}
			actions = append(actions, postgresAction)
		}
	}

	return actions, nil
}

func (p *PostgresActionParser) GetValidActions() []string {
	return []string{"AUTH", "QUERY"}
}

func (p *PostgresActionParser) ContainsAction(actions []postgresfern.PentestPostgresAction, target postgresfern.PentestPostgresAction) bool {
	for _, action := range actions {
		if action == target {
			return true
		}
	}
	return false
}
