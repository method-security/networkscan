package kerberos

import (
	"fmt"
	"net"
	"strings"
	"time"

	kerberosfern "github.com/Method-Security/networkscan/generated/go/pentest/kerberos"
	"github.com/Method-Security/networkscan/internal/common/ntlm"
	"github.com/Method-Security/networkscan/utils"
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
	Config        *config.Config
	Target        *Target
	etypeOverride []int32 // optional etype preference override
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
			KDC:   []string{utils.FormatHostPort(kcm.Target.Host, kcm.Target.Port)},
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
	defaultEtypes := []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.RC4_HMAC}
	if len(kcm.etypeOverride) > 0 {
		defaultEtypes = kcm.etypeOverride
	}
	cfg.LibDefaults.DefaultTGSEnctypeIDs = defaultEtypes
	cfg.LibDefaults.DefaultTktEnctypeIDs = defaultEtypes

	// Unset RenewableOK flag (match kerbtool behavior)
	types.UnsetFlag(&cfg.LibDefaults.KDCDefaultOptions, flags.RenewableOK)

	kcm.Config = cfg
	return cfg
}

// WithEtypes sets the etype preference order for the next CreateConfiguration call.
// Call before CreateConfiguration. Pass nil or empty to use defaults.
func (kcm *ClientManager) WithEtypes(etypes []int32) *ClientManager {
	kcm.etypeOverride = etypes
	return kcm
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
	var clientErr error

	// Check if NTLM hash is provided
	if pentestConfig.NtlmHash != nil && *pentestConfig.NtlmHash != "" {
		hashProcessor := ntlm.NewHashProcessor()
		hashBytes, hashErr := hashProcessor.ParseNTLMHash(*pentestConfig.NtlmHash)
		if hashErr != nil {
			return nil, "", fmt.Errorf("invalid NTLM hash: %v", hashErr)
		}
		krb5Client, clientErr = client.NewWithHash(requestingUser, strings.ToUpper(kcm.Target.Domain), hashBytes, kcm.Config, settings...)
	} else {
		krb5Client, clientErr = client.NewWithPassword(requestingUser, strings.ToUpper(kcm.Target.Domain), password, kcm.Config, settings...)
	}
	if clientErr != nil {
		return nil, "", fmt.Errorf("failed to create kerberos client: %v", clientErr)
	}

	return krb5Client, requestingUser, nil
}

// ParseTarget parses a target string into a Target. For IP addresses the domain
// is left empty — callers must supply the realm via --domain when targeting IPs.
func ParseTarget(targetStr string) (*Target, error) {
	host, port := utils.ParseHostPort(targetStr, 88)

	// IP addresses have no meaningful domain component; return empty domain so
	// the caller can fill it in from --domain without returning a spurious error.
	if net.ParseIP(host) != nil {
		return &Target{Host: host, Port: port, Domain: ""}, nil
	}

	// Extract domain from a FQDN (requires at least three labels, e.g. dc.corp.local).
	hostParts := strings.Split(host, ".")
	if len(hostParts) <= 2 {
		return nil, fmt.Errorf("cannot extract domain from hostname %q: supply --domain explicitly", host)
	}

	return &Target{
		Host:   host,
		Port:   port,
		Domain: strings.Join(hostParts[1:], "."),
	}, nil
}
