package smtp

import (
	smtp "github.com/Method-Security/networkscan/generated/go/smtp"
)

var authCommands = map[string]smtp.AuthCommand{
	"XOAUTH2":  smtp.AuthCommandXoauth2,
	"PLAIN":    smtp.AuthCommandPlain,
	"LOGIN":    smtp.AuthCommandLogin,
	"CRAM_MD5": smtp.AuthCommandCrammd5,
	"NTLM":     smtp.AuthCommandNtlm,
}
