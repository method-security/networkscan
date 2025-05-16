package smtp

import (
	smtpFern "github.com/Method-Security/networkscan/generated/go/enumerate/smtp"
)

var authCommands = map[string]smtpFern.AuthCommand{
	"XOAUTH2":  smtpFern.AuthCommandXoauth2,
	"PLAIN":    smtpFern.AuthCommandPlain,
	"LOGIN":    smtpFern.AuthCommandLogin,
	"CRAM_MD5": smtpFern.AuthCommandCrammd5,
	"NTLM":     smtpFern.AuthCommandNtlm,
}
