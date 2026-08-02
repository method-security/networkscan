package messages

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jfjallid/gokrb5/v9/types"
)

// ReplayCache detects replayed AP-REQ authenticators as required by RFC 4120
// section 3.2.3. A verifier that only checks the clock skew window would accept
// a captured AP-REQ replayed within that window; the replay cache rejects a
// second authenticator carrying the same (client, server, ctime+cusec) tuple.
//
// Entries are self-expiring: each is retained for the clock-skew duration passed
// to IsReplay, after which a replay of that authenticator is no longer possible
// (the skew check would reject it) and the entry can be discarded. Cleanup is
// performed opportunistically under the same lock as lookups, so a ReplayCache
// needs no background goroutine and is safe for concurrent use.
type ReplayCache struct {
	mux       sync.Mutex
	entries   map[string]time.Time // replay key -> entry expiry time (UTC)
	lastPurge time.Time
}

// defaultReplayCache is the process-wide replay cache used by APReq.Verify. A
// singleton is appropriate because the replay key is fully qualified by both the
// client and server principal names, so distinct services sharing the cache
// cannot collide.
var (
	defaultReplayCache     *ReplayCache
	defaultReplayCacheOnce sync.Once
)

func getDefaultReplayCache() *ReplayCache {
	defaultReplayCacheOnce.Do(func() {
		defaultReplayCache = &ReplayCache{entries: make(map[string]time.Time)}
	})
	return defaultReplayCache
}

// replayKey builds the cache key from the client and server principals and the
// authenticator's combined client time (ctime + cusec).
func replayKey(cname, sname types.PrincipalName, ct time.Time) string {
	var b strings.Builder
	b.WriteString(cname.PrincipalNameString())
	b.WriteByte('|')
	b.WriteString(sname.PrincipalNameString())
	b.WriteByte('|')
	b.WriteString(strconv.FormatInt(ct.UnixNano(), 10))
	return b.String()
}

// IsReplay reports whether the authenticator a (presented to service sname) has
// already been seen within the clock-skew duration d. If it has not, the
// authenticator is recorded and false is returned. d should match the clock-skew
// window enforced by the caller so that an entry lives at least as long as a
// replay could be accepted by the skew check.
func (c *ReplayCache) IsReplay(sname types.PrincipalName, a types.Authenticator, d time.Duration) bool {
	ct := a.CTime.Add(time.Duration(a.Cusec) * time.Microsecond)
	key := replayKey(a.CName, sname, ct)

	c.mux.Lock()
	defer c.mux.Unlock()
	now := time.Now().UTC()
	c.purgeLocked(now)
	if _, ok := c.entries[key]; ok {
		return true
	}
	c.entries[key] = now.Add(d)
	return false
}

// purgeLocked removes expired entries, throttled so the O(n) sweep runs at most
// once per second under high request rates. The caller must hold c.mux.
func (c *ReplayCache) purgeLocked(now time.Time) {
	// Sweep at most once per second of wall-clock to bound the O(n) cost under
	// high request rates; entries that outlive their expiry by up to a second
	// are still rejected as replays in the meantime, so correctness holds.
	if now.Sub(c.lastPurge) < time.Second {
		return
	}
	for k, expiry := range c.entries {
		if now.After(expiry) {
			delete(c.entries, k)
		}
	}
	c.lastPurge = now
}
