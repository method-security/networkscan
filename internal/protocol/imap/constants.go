package imap

const (
	// DefaultImapPort is the IANA-assigned port for plain-text IMAP.
	DefaultImapPort = 143
	// DefaultImapsPort is the IANA-assigned port for IMAP over implicit TLS (RFC 8314).
	DefaultImapsPort = 993
	// DefaultMaxMessages caps UID FETCH output when the caller does not set a value.
	DefaultMaxMessages = 50
	// DefaultTargetFolder is the mailbox used for FETCH_HEADERS/SEARCH when unspecified.
	DefaultTargetFolder = "INBOX"
)
