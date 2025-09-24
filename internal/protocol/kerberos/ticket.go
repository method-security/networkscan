package kerberos

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/jfjallid/gokrb5/v8/client"
	"github.com/jfjallid/gokrb5/v8/config"
	"github.com/jfjallid/gokrb5/v8/credentials"
	"github.com/jfjallid/gokrb5/v8/iana/nametype"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/types"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// TicketInfo contains information extracted from a Kerberos ticket
type TicketInfo struct {
	Base64    string
	Principal string
	Realm     string
}

// TicketManager handles Kerberos ticket operations
type TicketManager struct {
	Client *client.Client
	Config *config.Config
}

// NewTicketManager creates a new ticket manager
func NewTicketManager(client *client.Client, config *config.Config) *TicketManager {
	return &TicketManager{
		Client: client,
		Config: config,
	}
}

// RequestServiceTicket performs service ticket acquisition (with optional S4U2Self and S4U2Proxy for impersonation)
func (tm *TicketManager) RequestServiceTicket(ctx context.Context, requestingUser, userDomain, impersonateUser, spn string) (*TicketInfo, error) {
	log := svc1log.FromContext(ctx)

	// Step 1: Get TGT for delegation user
	tgt, sessionKey, err := tm.Client.GetTGT(strings.ToUpper(userDomain))
	if err != nil {
		return nil, fmt.Errorf("failed to get TGT: %v", err)
	}

	log.Debug("Successfully obtained TGT for requesting user")

	if impersonateUser != "" {
		// Step 2: Perform S4U2Self to get service ticket for impersonated user
		s4uManager := NewS4UManager(tm.Client, tm.Config)

		s4u2SelfTicket, err := s4uManager.PerformS4U2Self(ctx, requestingUser, userDomain, impersonateUser, tgt, sessionKey)
		if err != nil {
			return nil, fmt.Errorf("S4U2Self failed: %v", err)
		}

		log.Debug("Successfully performed S4U2Self")

		// Step 3: Perform S4U2Proxy to get service ticket for target SPN
		err = s4uManager.PerformS4U2Proxy(ctx, requestingUser, userDomain, impersonateUser, tgt, s4u2SelfTicket, sessionKey, spn)
		if err != nil {
			return nil, fmt.Errorf("S4U2Proxy failed: %v", err)
		}

		log.Debug("Successfully performed S4U2Proxy")
	} else {
		// Regular service ticket request without impersonation
		_, _, err := tm.Client.GetServiceTicket(spn)
		if err != nil {
			return nil, fmt.Errorf("failed to get service ticket: %v", err)
		}

		log.Debug("Successfully obtained service ticket")
	}

	// Step 4: Generate base64 encoded ccache
	var ticketPrincipal string
	if impersonateUser != "" {
		ticketPrincipal = impersonateUser
	} else {
		ticketPrincipal = requestingUser
	}

	ticketBase64, err := tm.GenerateTicketBase64(ticketPrincipal, strings.ToUpper(userDomain), spn)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ticket: %v", err)
	}

	return &TicketInfo{
		Base64:    ticketBase64,
		Principal: ticketPrincipal,
		Realm:     strings.ToUpper(userDomain),
	}, nil
}

// GenerateTicketBase64 generates the acquired ticket as a base64-encoded ccache
func (tm *TicketManager) GenerateTicketBase64(impersonateUser, userDomain, spn string) (string, error) {
	// Create ccache
	cache := credentials.NewV4CCache()
	clientPrincipal := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, impersonateUser)
	principal := credentials.NewPrincipal(clientPrincipal, userDomain)
	cache.SetDefaultPrincipal(principal)
	cache.SetKDCTimeOffset(0xFFFFFFFF, 0)

	// Save the service ticket
	err := tm.Client.SaveSPNToCCache(cache, clientPrincipal, userDomain, spn, "")
	if err != nil {
		return "", fmt.Errorf("failed to save SPN to ccache: %v", err)
	}

	// Marshal ccache to bytes
	cacheBytes, err := cache.Marshal()
	if err != nil {
		return "", fmt.Errorf("failed to marshal ccache: %v", err)
	}

	// Encode as base64
	ticketBase64 := base64.StdEncoding.EncodeToString(cacheBytes)

	return ticketBase64, nil
}

// GetTGT retrieves a Ticket Granting Ticket for the specified domain
func (tm *TicketManager) GetTGT(userDomain string) (messages.Ticket, types.EncryptionKey, error) {
	return tm.Client.GetTGT(strings.ToUpper(userDomain))
}
