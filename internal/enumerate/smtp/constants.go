package smtp

import (
	// Generated
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
)

var authCommands = map[string]protocol.SmtpAuthCommand{
	"XOAUTH2":  protocol.SmtpAuthCommandXoauth2,
	"PLAIN":    protocol.SmtpAuthCommandPlain,
	"LOGIN":    protocol.SmtpAuthCommandLogin,
	"CRAM_MD5": protocol.SmtpAuthCommandCrammd5,
	"NTLM":     protocol.SmtpAuthCommandNtlm,
}

var defaultUsernames = []string{
	"root", "admin", "administrator", "postmaster", "webmaster",
	"info", "support", "sales", "contact", "abuse",
	"noc", "security", "hostmaster", "mailer-daemon",
	"nobody", "mail", "ftp", "www", "www-data",
	"test", "guest", "user", "operator",
}
