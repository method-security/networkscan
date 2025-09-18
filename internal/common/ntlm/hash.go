package ntlm

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// StandardLMHash is the standard empty LM hash value (always the same)
const StandardLMHash = "aad3b435b51404eeaad3b435b51404ee"

// EmptyNTHash is the empty NT hash (for empty password)
const EmptyNTHash = "31D6CFE0D16AE931B73C59D7E0C089C0"

// HashProcessor provides utilities for processing NTLM hashes
type HashProcessor struct{}

// NewHashProcessor creates a new NTLM hash processor
func NewHashProcessor() *HashProcessor {
	return &HashProcessor{}
}

// ParseNTLMHash parses an NTLM hash and returns the NT portion as bytes
func (p *HashProcessor) ParseNTLMHash(ntlmHash string) ([]byte, error) {
	if len(ntlmHash) == 32 {
		// Only NT hash provided (32 hex chars), use directly
		return hex.DecodeString(ntlmHash)
	} else if len(ntlmHash) == 65 && ntlmHash[32] == ':' {
		// LM:NT format provided, extract NT portion (after colon)
		ntHashStr := ntlmHash[33:] // Skip "LM:" part
		return hex.DecodeString(ntHashStr)
	}
	return nil, fmt.Errorf("invalid NTLM hash format: expected 32 hex chars (NT only) or 65 chars (LM:NT)")
}

// ProcessHashForLDAP processes an NTLM hash for LDAP authentication (returns LM:NT format)
func (p *HashProcessor) ProcessHashForLDAP(ntlmHash string) string {
	if len(ntlmHash) == 32 {
		// Only NT hash provided (32 hex chars), prepend standard LM hash
		return StandardLMHash + ":" + ntlmHash
	}
	// Assume it's already in LM:NT format
	return ntlmHash
}

// IsValidNTHash checks if a hash looks like a valid NT hash
func (p *HashProcessor) IsValidNTHash(hash string) bool {
	return len(hash) == 32 && strings.ToUpper(hash) != EmptyNTHash
}

// IsEmptyNTHash checks if the hash represents an empty password
func (p *HashProcessor) IsEmptyNTHash(hash string) bool {
	return strings.ToUpper(hash) == EmptyNTHash
}
