package client

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jfjallid/gofork/encoding/asn1"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/types"
)

// cacheKey canonicalises an SPN for use as a cache map key. Active Directory /
// Entra canonicalise the host portion of a service principal to the case stored
// in the directory, so a ticket requested as "cifs/SRV01.example.com" comes
// back (and is stored) as "cifs/srv01.example.com". Keying on a lower-cased
// form makes a subsequent lookup with any casing hit the same entry instead of
// triggering a redundant KDC round-trip. The CacheEntry preserves the original
// (KDC-canonical) SPN in its SPN field; only the map key is folded.
//
// NOTE: the key carries no realm. Two realms holding the same service/host SPN
// would collide here; this is a pre-existing limitation unchanged by the case
// folding. See unmitigated_risks.md.
func cacheKey(spn string) string {
	return strings.ToLower(spn)
}

// Cache for service tickets held by the client.
type Cache struct {
	Entries map[string]CacheEntry
	mux     sync.RWMutex
}

// CacheEntry holds details for a cache entry.
type CacheEntry struct {
	SPN        string
	Ticket     messages.Ticket `json:"-"`
	AuthTime   time.Time
	StartTime  time.Time
	EndTime    time.Time
	RenewTill  time.Time
	SessionKey types.EncryptionKey `json:"-"`
	Flags      asn1.BitString
}

// NewCache creates a new client ticket cache instance.
func NewCache() *Cache {
	return &Cache{
		Entries: map[string]CacheEntry{},
	}
}

// getEntry returns a cache entry that matches the SPN.
func (c *Cache) getEntry(spn string) (CacheEntry, bool) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	e, ok := (*c).Entries[cacheKey(spn)]
	return e, ok
}

func (c *Cache) getEntries() []CacheEntry {
	c.mux.RLock()
	defer c.mux.RUnlock()
	res := make([]CacheEntry, 0, len(c.Entries))
	for _, entry := range c.Entries {
		res = append(res, entry)
	}
	return res
}

// JSON returns information about the cached service tickets in a JSON format.
func (c *Cache) JSON() (string, error) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	var es []CacheEntry
	keys := make([]string, 0, len(c.Entries))
	for k := range c.Entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		es = append(es, c.Entries[k])
	}
	b, err := json.MarshalIndent(&es, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// addEntry adds a ticket to the cache.
func (c *Cache) addEntry(tkt messages.Ticket, authTime, startTime, endTime, renewTill time.Time, sessionKey types.EncryptionKey, flags asn1.BitString) CacheEntry {
	spn := tkt.SName.PrincipalNameString()
	c.mux.Lock()
	defer c.mux.Unlock()
	(*c).Entries[cacheKey(spn)] = CacheEntry{
		SPN:        spn,
		Ticket:     tkt,
		AuthTime:   authTime,
		StartTime:  startTime,
		EndTime:    endTime,
		RenewTill:  renewTill,
		SessionKey: sessionKey,
		Flags:      flags,
	}
	return c.Entries[cacheKey(spn)]
}

// clear deletes all the cache entries
func (c *Cache) clear() {
	c.mux.Lock()
	defer c.mux.Unlock()
	for k := range c.Entries {
		delete(c.Entries, k)
	}
}

// RemoveEntry removes the cache entry for the defined SPN.
func (c *Cache) RemoveEntry(spn string) {
	c.mux.Lock()
	defer c.mux.Unlock()
	delete(c.Entries, cacheKey(spn))
}

// GetCachedTicket returns a ticket from the cache for the SPN.
// Only a ticket that is currently valid will be returned.
func (cl *Client) GetCachedTicket(spn string) (messages.Ticket, types.EncryptionKey, bool) {
	if e, ok := cl.cache.getEntry(spn); ok {
		//If within time window of ticket return it
		if time.Now().UTC().After(e.StartTime) && time.Now().UTC().Before(e.EndTime) {
			cl.Log("ticket received from cache for %s", spn)
			return e.Ticket, e.SessionKey, true
		} else if time.Now().UTC().Before(e.RenewTill) {
			e, err := cl.renewTicket(e)
			if err != nil {
				return e.Ticket, e.SessionKey, false
			}
			return e.Ticket, e.SessionKey, true
		}
		log.Debugf("cached ticket does not match validity time. Now: %s cache starttime: %s, endtime: %s, renewtill: %s\n", time.Now().UTC(), e.StartTime, e.EndTime, e.RenewTill)
	}
	var tkt messages.Ticket
	var key types.EncryptionKey
	return tkt, key, false
}

// renewTicket renews a cache entry ticket.
// To renew from outside the client package use GetCachedTicket
func (cl *Client) renewTicket(e CacheEntry) (CacheEntry, error) {
	spn := e.Ticket.SName
	_, _, err := cl.TGSREQGenerateAndExchange(spn, e.Ticket.Realm, e.Ticket, e.SessionKey, true)
	if err != nil {
		return e, err
	}
	e, ok := cl.cache.getEntry(e.Ticket.SName.PrincipalNameString())
	if !ok {
		return e, errors.New("ticket was not added to cache")
	}
	cl.Log("ticket renewed for %s (EndTime: %v)", spn.PrincipalNameString(), e.EndTime)
	return e, nil
}

func (cl *Client) RemoveTicket(spn string) {
	cl.cache.RemoveEntry(spn)
}
