package config

import (
	"strings"
	"sync"
)

// CanonicalRealm returns a comparison-friendly form of a realm name: any
// trailing dot is stripped and the result is ASCII-uppercased. Use this only
// for map keys and equivalence checks. Do not feed the result back onto the
// wire or into key-derivation routines: pre-auth salt computation depends on
// the literal realm bytes the KDC has registered, which is not required to
// be uppercase.
func CanonicalRealm(r string) string {
	return strings.ToUpper(strings.TrimSuffix(r, "."))
}

// EqualRealm reports whether two realm names refer to the same realm by
// canonical-form comparison only. It does not consult any runtime alias
// table; for alias-aware comparison use Client.IsSameRealm.
func EqualRealm(a, b string) bool {
	return CanonicalRealm(a) == CanonicalRealm(b)
}

// RealmsEquivalent reports whether a and b name the same realm, consulting the
// alias table when non-nil and otherwise falling back to canonical-form
// equality. It is the alias-aware form of EqualRealm and is suitable for the
// realm consistency checks in KDC reply verification, where the KDC may return
// a realm in a different (e.g. canonical DNS) form than the one requested.
func RealmsEquivalent(aliases *RealmAliases, a, b string) bool {
	if aliases == nil {
		return EqualRealm(a, b)
	}
	return aliases.Resolve(a) == aliases.Resolve(b)
}

// RealmAliases records equivalences between alternative names for the same
// realm. The most common case is a NetBIOS short name and a DNS-style long
// name referring to the same Active Directory domain (e.g. "CORP" and
// "CORP.EXAMPLE.COM"). It is safe for concurrent use.
//
// Aliases should only be added from authoritative sources: an explicit
// configuration entry, a krbtgt pair observed in a CCache, or a KDC response
// that disagrees with the form used in the request. Inferring aliases from
// string surgery on a realm name (for example, assuming the NetBIOS short
// name equals the first DNS label) is unsafe and must not be done.
type RealmAliases struct {
	mu      sync.RWMutex
	toCanon map[string]string // CanonicalRealm(alias) -> CanonicalRealm(canonical)
}

// NewRealmAliases returns an empty alias table ready for use.
func NewRealmAliases() *RealmAliases {
	return &RealmAliases{toCanon: make(map[string]string)}
}

// Add records that alias and canonical name the same realm. The canonical
// argument identifies the authoritative form, typically the form returned
// by the KDC. Either side may already have its own alias recorded; the
// resulting chain is collapsed so Resolve never needs to follow more than
// one hop. Empty inputs are ignored.
func (a *RealmAliases) Add(alias, canonical string) {
	if alias == "" || canonical == "" {
		return
	}
	ak := CanonicalRealm(alias)
	ck := CanonicalRealm(canonical)
	if ak == ck {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Follow any existing chain on the canonical side so the table stays flat.
	visited := map[string]bool{ck: true}
	for {
		next, ok := a.toCanon[ck]
		if !ok || next == ck || visited[next] {
			break
		}
		ck = next
		visited[ck] = true
	}
	a.toCanon[ak] = ck
}

// Resolve returns the canonical form of r, consulting the alias table.
// Realms with no recorded alias resolve to CanonicalRealm(r). The empty
// string resolves to the empty string. A nil receiver is treated as an empty
// table, so callers holding an optional alias table need not nil-check.
func (a *RealmAliases) Resolve(r string) string {
	if r == "" {
		return ""
	}
	k := CanonicalRealm(r)
	if a == nil {
		return k
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if c, ok := a.toCanon[k]; ok {
		return c
	}
	return k
}

// Equivalents returns the canonical form of r along with every known alias
// for the same realm. The returned slice always contains at least one
// element (the canonical form) and is in unspecified order.
func (a *RealmAliases) Equivalents(r string) []string {
	canon := a.Resolve(r)
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := []string{canon}
	for alias, c := range a.toCanon {
		if c == canon && alias != canon {
			out = append(out, alias)
		}
	}
	return out
}

// AddAll copies every alias from other into a. It is intended for snapshot-
// style propagation (e.g. seeding a per-Client table from a Config table)
// where the destination should be independent of subsequent mutations to
// the source.
func (a *RealmAliases) AddAll(other *RealmAliases) {
	if other == nil || a == other {
		return
	}
	other.mu.RLock()
	entries := make(map[string]string, len(other.toCanon))
	for k, v := range other.toCanon {
		entries[k] = v
	}
	other.mu.RUnlock()
	for alias, canonical := range entries {
		a.Add(alias, canonical)
	}
}

// parseLines parses the lines of the [realm_aliases] section of krb5.conf.
// Each non-comment, non-blank line must be of the form `alias = canonical`,
// where `alias` is any alternative name (a NetBIOS short name being the
// common case) and `canonical` is the form returned by Resolve.
func (a *RealmAliases) parseLines(lines []string) error {
	for _, line := range lines {
		if idx := strings.IndexAny(line, "#;"); idx != -1 {
			line = line[:idx]
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.Contains(line, "=") {
			return InvalidErrorf("realm_aliases line (%s)", line)
		}
		p := strings.SplitN(line, "=", 2)
		alias := strings.TrimSpace(p[0])
		canonical := strings.TrimSpace(p[1])
		a.Add(alias, canonical)
	}
	return nil
}
