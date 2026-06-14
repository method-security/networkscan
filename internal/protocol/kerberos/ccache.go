package kerberos

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/jfjallid/gokrb5/v8/credentials"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/types"
)

// LoadCCacheFromBase64 decodes a base64-encoded CCache and unmarshals it.
func LoadCCacheFromBase64(b string) (*credentials.CCache, error) {
	raw, err := base64.StdEncoding.DecodeString(b)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 ccache: %w", err)
	}
	cache := new(credentials.CCache)
	if err := cache.Unmarshal(raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ccache: %w", err)
	}
	return cache, nil
}

// WriteCCacheToFile marshals the CCache and writes it to the given path with 0600 permissions.
func WriteCCacheToFile(cache *credentials.CCache, path string) error {
	b, err := cache.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal ccache: %w", err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		return fmt.Errorf("failed to write ccache to %s: %w", path, err)
	}
	return nil
}

// LoadTGTFromCCache walks a CCache looking for the krbtgt entry for the given realm.
// It returns the TGT ticket, session key, and true if found; otherwise false.
func LoadTGTFromCCache(cache *credentials.CCache, realm string) (tgt messages.Ticket, sessionKey types.EncryptionKey, ok bool) {
	upperRealm := strings.ToUpper(realm)

	for _, cred := range cache.GetEntries() {
		// krbtgt entry has Server principal name "krbtgt/<REALM>"
		sname := cred.Server.PrincipalName
		serverRealm := cred.Server.Realm
		if len(sname.NameString) >= 2 &&
			strings.EqualFold(sname.NameString[0], "krbtgt") &&
			strings.EqualFold(serverRealm, upperRealm) {

			// Unmarshal the raw ticket bytes into messages.Ticket
			var ticket messages.Ticket
			if err := ticket.Unmarshal(cred.Ticket); err != nil {
				continue
			}
			return ticket, cred.Key, true
		}
	}
	return messages.Ticket{}, types.EncryptionKey{}, false
}
