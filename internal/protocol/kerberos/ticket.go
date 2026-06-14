package kerberos

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

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

	// Enhanced ticket metadata
	ServicePrincipal    *string
	StartTime           *time.Time
	EndTime             *time.Time
	RenewUntil          *time.Time
	TicketFlags         *string
	EncryptionType      *string
	KeyVersionNumber    *int
	Algorithm           *string
	TicketVersionNumber *int
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

		// Step 3: Perform S4U2Proxy to get service ticket for target SPN.
		// The delegated ticket is retrieved internally by the gokrb5 client cache
		// (used by tryGetServiceTicketFromClient below), so we discard the
		// explicit return here — the existing service-ticket flow already
		// reads it back from the client cache for ccache emission.
		if _, err = s4uManager.PerformS4U2Proxy(ctx, requestingUser, userDomain, impersonateUser, tgt, s4u2SelfTicket, sessionKey, spn); err != nil {
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

	// Common path: Extract ticket information after successful acquisition
	var ticketPrincipal string
	if impersonateUser != "" {
		ticketPrincipal = impersonateUser
	} else {
		ticketPrincipal = requestingUser
	}

	// Use modular extraction method that works for both regular and impersonation flows
	return tm.extractEnhancedTicketInfo(spn, ticketPrincipal, strings.ToUpper(userDomain))
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

// extractEnhancedTicketInfo extracts comprehensive ticket information for both regular and impersonation flows
func (tm *TicketManager) extractEnhancedTicketInfo(spn, principal, realm string) (*TicketInfo, error) {
	ticketInfo := &TicketInfo{
		Principal:        principal,
		Realm:            realm,
		ServicePrincipal: &spn,
	}

	// Try to extract enhanced information by attempting to get the service ticket from client
	// This works for both regular tickets and tickets added via S4U delegation
	if ticket, sessionKey, err := tm.tryGetServiceTicketFromClient(spn); err == nil {
		// Successfully retrieved ticket - extract enhanced metadata
		tm.populateTicketMetadata(ticketInfo, ticket, sessionKey)
	}

	// Generate base64 encoded ccache and extract timing info from it
	ticketBase64, err := tm.generateTicketWithTiming(ticketInfo, principal, realm, spn)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ticket: %v", err)
	}
	ticketInfo.Base64 = ticketBase64

	return ticketInfo, nil
}

// tryGetServiceTicketFromClient attempts to retrieve the service ticket from the client
// This works for both regular tickets and tickets added via S4U delegation
func (tm *TicketManager) tryGetServiceTicketFromClient(spn string) (messages.Ticket, types.EncryptionKey, error) {
	// Try to get the service ticket - this should work whether it was obtained
	// through regular GetServiceTicket or added via S4U delegation
	return tm.Client.GetServiceTicket(spn)
}

// generateTicketWithTiming generates the base64 ccache AND extracts timing information from it
func (tm *TicketManager) generateTicketWithTiming(ticketInfo *TicketInfo, principal, realm, spn string) (string, error) {
	// Create ccache
	cache := credentials.NewV4CCache()
	clientPrincipal := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, principal)
	principalObj := credentials.NewPrincipal(clientPrincipal, realm)
	cache.SetDefaultPrincipal(principalObj)
	cache.SetKDCTimeOffset(0xFFFFFFFF, 0)

	// Save the service ticket to ccache - this includes timing information!
	err := tm.Client.SaveSPNToCCache(cache, clientPrincipal, realm, spn, "")
	if err != nil {
		return "", fmt.Errorf("failed to save SPN to ccache: %v", err)
	}

	// Extract timing information from the ccache entries BEFORE marshaling
	tm.extractTimingFromCCache(ticketInfo, cache, spn)

	// Marshal ccache to bytes
	cacheBytes, err := cache.Marshal()
	if err != nil {
		return "", fmt.Errorf("failed to marshal ccache: %v", err)
	}

	// Encode as base64
	return base64.StdEncoding.EncodeToString(cacheBytes), nil
}

// extractTimingFromCCache extracts timing information from the ccache entries
func (tm *TicketManager) extractTimingFromCCache(ticketInfo *TicketInfo, cache *credentials.CCache, spn string) {
	// Iterate through cache entries to find our service ticket
	for _, entry := range cache.GetEntries() {
		// Check if this entry matches our SPN
		if tm.matchesSPN(entry, spn) {
			// Extract timing information from the cache entry
			if !entry.StartTime.IsZero() {
				ticketInfo.StartTime = &entry.StartTime
			}
			if !entry.EndTime.IsZero() {
				ticketInfo.EndTime = &entry.EndTime
			}
			if !entry.RenewTill.IsZero() {
				ticketInfo.RenewUntil = &entry.RenewTill
			}
			break
		}
	}
}

// matchesSPN checks if a cache entry matches the given SPN
func (tm *TicketManager) matchesSPN(entry *credentials.Credential, spn string) bool {
	// Convert entry SPN to string and compare (from Server.PrincipalName)
	if len(entry.Server.PrincipalName.NameString) >= 2 {
		entrySPN := strings.Join(entry.Server.PrincipalName.NameString, "/")
		return entrySPN == spn
	}
	return false
}

// populateTicketMetadata populates the TicketInfo with enhanced metadata from the ticket and session key
func (tm *TicketManager) populateTicketMetadata(ticketInfo *TicketInfo, ticket messages.Ticket, sessionKey types.EncryptionKey) {
	// Extract ticket version number
	if ticket.TktVNO != 0 {
		tktVNO := ticket.TktVNO
		ticketInfo.TicketVersionNumber = &tktVNO
	}

	// Extract key version number if available
	if ticket.EncPart.KVNO != 0 {
		kvno := ticket.EncPart.KVNO
		ticketInfo.KeyVersionNumber = &kvno
	}

	// Extract encryption type from session key
	if sessionKey.KeyType != 0 {
		encType := tm.getEncryptionTypeName(sessionKey.KeyType)
		ticketInfo.EncryptionType = &encType
		ticketInfo.Algorithm = &encType // For compatibility
	}

	// Try to extract timing information from decrypted ticket part
	tm.extractTimingInfo(ticketInfo, ticket, sessionKey)
}

// extractTimingInfo attempts to extract timing information from the ticket's encrypted part
func (tm *TicketManager) extractTimingInfo(ticketInfo *TicketInfo, ticket messages.Ticket, sessionKey types.EncryptionKey) {
	// Check if ticket already has decrypted part
	if ticket.DecryptedEncPart.EndTime.IsZero() {
		// Try to decrypt the ticket part to access timing information
		// Note: This requires the service key, which we typically don't have as a client
		// The timing info would need to be extracted differently, possibly from the TGS response
		return
	}

	// If we have decrypted timing info, extract it
	if !ticket.DecryptedEncPart.StartTime.IsZero() {
		ticketInfo.StartTime = &ticket.DecryptedEncPart.StartTime
	}

	if !ticket.DecryptedEncPart.EndTime.IsZero() {
		ticketInfo.EndTime = &ticket.DecryptedEncPart.EndTime
	}

	if !ticket.DecryptedEncPart.RenewTill.IsZero() {
		ticketInfo.RenewUntil = &ticket.DecryptedEncPart.RenewTill
	}
}

// getEncryptionTypeName returns the human-readable name for an encryption type
func (tm *TicketManager) getEncryptionTypeName(etypeID int32) string {
	switch etypeID {
	case 17:
		return "AES128-CTS-HMAC-SHA1-96"
	case 18:
		return "AES256-CTS-HMAC-SHA1-96"
	case 19:
		return "AES128-CTS-HMAC-SHA256-128"
	case 20:
		return "AES256-CTS-HMAC-SHA384-192"
	case 23:
		return "RC4-HMAC"
	case 16:
		return "DES3-CBC-SHA1-KD"
	default:
		return fmt.Sprintf("Unknown-EType-%d", etypeID)
	}
}
