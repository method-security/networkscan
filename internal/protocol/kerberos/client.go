package kerberos

import (
	"fmt"
	"strings"
	"time"

	kerberosfern "github.com/Method-Security/networkscan/generated/go/pentest/kerberos"
	"github.com/Method-Security/networkscan/internal/common/ntlm"
	"github.com/jfjallid/gokrb5/v8/client"
	"github.com/jfjallid/gokrb5/v8/config"
	"github.com/jfjallid/gokrb5/v8/iana/etypeID"
	"github.com/jfjallid/gokrb5/v8/iana/flags"
	"github.com/jfjallid/gokrb5/v8/types"
)

// Target represents a parsed Kerberos target
type Target struct {
	Host   string
	Port   int
	Domain string
}

// ClientManager handles Kerberos client configuration and creation
type ClientManager struct {
	Config *config.Config
	Target *Target
}

// NewClientManager creates a new Kerberos client manager
func NewClientManager(target *Target) *ClientManager {
	return &ClientManager{
		Target: target,
	}
}

// CreateConfiguration creates a Kerberos configuration for the target
func (kcm *ClientManager) CreateConfiguration() *config.Config {
	// Create Kerberos configuration (match kerbtool behavior)
	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = false // Disable DNS lookup since we're specifying KDC directly
	cfg.LibDefaults.DefaultRealm = strings.ToUpper(kcm.Target.Domain)
	cfg.Realms = []config.Realm{
		{
			Realm: strings.ToUpper(kcm.Target.Domain),
			KDC:   []string{fmt.Sprintf("%s:%d", kcm.Target.Host, kcm.Target.Port)},
		},
	}
	cfg.DomainRealm = map[string]string{
		fmt.Sprintf(".%s", strings.ToLower(kcm.Target.Domain)): strings.ToUpper(kcm.Target.Domain),
	}
	cfg.LibDefaults.Forwardable = true

	// Set ticket lifetimes
	ticketDuration := time.Hour * 10
	cfg.LibDefaults.RenewLifetime = ticketDuration
	cfg.LibDefaults.TicketLifetime = ticketDuration

	// Set up encryption preferences (match kerbtool behavior)
	cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.RC4_HMAC}
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.RC4_HMAC}

	// Unset RenewableOK flag (match kerbtool behavior)
	types.UnsetFlag(&cfg.LibDefaults.KDCDefaultOptions, flags.RenewableOK)

	kcm.Config = cfg
	return cfg
}

// CreateClientFromConfig creates a Kerberos client from the provided config
func (kcm *ClientManager) CreateClientFromConfig(pentestConfig *kerberosfern.PentestKerberosConfig) (*client.Client, string, error) {
	if kcm.Config == nil {
		kcm.CreateConfiguration()
	}

	// Create client settings
	settings := []func(*client.Settings){client.DisablePAFXFAST(true)}

	// Use first available credential method from unified auth config
	if len(pentestConfig.Usernames) == 0 {
		return nil, "", fmt.Errorf("no username provided in auth config")
	}

	requestingUser := pentestConfig.Usernames[0]
	var password string
	if len(pentestConfig.Passwords) > 0 {
		password = pentestConfig.Passwords[0]
	}

	var krb5Client *client.Client

	// Check if NTLM hash is provided
	if pentestConfig.NtlmHash != nil && *pentestConfig.NtlmHash != "" {
		hashProcessor := ntlm.NewHashProcessor()
		hashBytes, hashErr := hashProcessor.ParseNTLMHash(*pentestConfig.NtlmHash)
		if hashErr != nil {
			return nil, "", fmt.Errorf("invalid NTLM hash: %v", hashErr)
		}
		krb5Client = client.NewWithHash(requestingUser, strings.ToUpper(kcm.Target.Domain), hashBytes, kcm.Config, settings...)
	} else {
		krb5Client = client.NewWithPassword(requestingUser, strings.ToUpper(kcm.Target.Domain), password, kcm.Config, settings...)
	}

	return krb5Client, requestingUser, nil
}

// ParseTarget parses a target string into components
func ParseTarget(targetStr string) (*Target, error) {
	// Split target into host and port
	parts := strings.Split(targetStr, ":")
	if len(parts) < 2 {
		return nil, fmt.Errorf("target must include port (e.g., dc.domain.com:88)")
	}

	host := parts[0]
	port := 88 // Default Kerberos port
	if len(parts) > 1 {
		if p, err := fmt.Sscanf(parts[1], "%d", &port); err != nil || p != 1 {
			port = 88 // Fall back to default
		}
	}

	// Extract domain from hostname
	domain := ""
	hostParts := strings.Split(host, ".")
	if len(hostParts) > 2 {
		domain = strings.Join(hostParts[1:], ".")
	} else {
		return nil, fmt.Errorf("cannot extract domain from hostname: %s", host)
	}

	return &Target{
		Host:   host,
		Port:   port,
		Domain: domain,
	}, nil
}
