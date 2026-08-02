// Package client provides a client library and methods for Kerberos 5 authentication.
package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jfjallid/gofork/encoding/asn1"
	"github.com/jfjallid/gokrb5/v9/config"
	"github.com/jfjallid/gokrb5/v9/credentials"
	"github.com/jfjallid/gokrb5/v9/crypto"
	"github.com/jfjallid/gokrb5/v9/crypto/etype"
	"github.com/jfjallid/gokrb5/v9/iana/errorcode"
	"github.com/jfjallid/gokrb5/v9/iana/etypeID"
	"github.com/jfjallid/gokrb5/v9/iana/nametype"
	"github.com/jfjallid/gokrb5/v9/keytab"
	"github.com/jfjallid/gokrb5/v9/krberror"
	"github.com/jfjallid/gokrb5/v9/messages"
	"github.com/jfjallid/gokrb5/v9/types"
	"github.com/jfjallid/golog"
)

// TODO Move away from the logger in Client.settings so we can log without a client
var log = golog.Get("github.com/jfjallid/gokrb5/v9").SetDisplayName("gokrb5")

// Client side configuration and state.
type Client struct {
	Credentials      *credentials.Credentials
	Config           *config.Config
	settings         *Settings
	sessions         *sessions
	cache            *Cache
	aliases          *config.RealmAliases // runtime-learned realm-name equivalences, per-client to avoid cross-client pollution when a Config is shared
	pkInitClient     any                  // *pkinit.PKINITClient, set during PKINIT AS exchange
	pkInitDerivedKey *types.EncryptionKey // DH-derived key from PKINIT, needed for PAC credential decryption
}

// newClientAliases returns a per-client alias table seeded from the static
// aliases declared in the Config's [realm_aliases] section. The seed is a
// snapshot: later mutations to the Config's table do not propagate, and
// runtime additions stay scoped to one client. Safe to call with a nil
// Config.
func newClientAliases(cfg *config.Config) *config.RealmAliases {
	a := config.NewRealmAliases()
	if cfg != nil && cfg.RealmAliases != nil {
		a.AddAll(cfg.RealmAliases)
	}
	return a
}

// PKINITDerivedKey returns the DH-derived key from PKINIT authentication.
// This key is the AS reply key used to decrypt PAC_CREDENTIAL_INFO.
// Returns nil if the client did not authenticate via PKINIT.
func (cl *Client) PKINITDerivedKey() *types.EncryptionKey {
	return cl.pkInitDerivedKey
}

// NewWithPassword creates a new client from a password credential.
// Set the realm to empty string to use the default realm from config.
func NewWithPassword(username, realm, password string, krb5conf *config.Config, settings ...func(*Settings)) (*Client, error) {
	creds := credentials.New(username, realm)
	aliases := newClientAliases(krb5conf)
	return &Client{
		Credentials: creds.WithPassword(password),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
			aliases: aliases,
		},
		cache:   NewCache(),
		aliases: aliases,
	}, nil
}

// NewWithHash creates a new client from an NT Hash.
func NewWithHash(username, realm string, hash []byte, krb5conf *config.Config, settings ...func(*Settings)) (*Client, error) {
	creds := credentials.New(username, realm)
	aliases := newClientAliases(krb5conf)
	c := &Client{
		Config:   krb5conf,
		settings: NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
			aliases: aliases,
		},
		cache:   NewCache(),
		aliases: aliases,
	}
	if len(hash) == 16 {
		c.Credentials = creds.WithNTHash(hash)
	} else {
		return nil, fmt.Errorf("invalid hash provided for new client")
	}

	return c, nil
}

// NewWithKey creates a new client from a user's AES Key 128/256 bit.
// The etype is inferred from the key length and assumes the RFC 3962 SHA-1
// variants (aes128-cts-hmac-sha1-96 / aes256-cts-hmac-sha1-96). For RFC 8009
// SHA-2 keys use NewWithKeyEtype since those cannot be distinguished from the
// SHA-1 variants by key length alone.
func NewWithKey(username, realm string, key []byte, krb5conf *config.Config, settings ...func(*Settings)) (*Client, error) {
	return NewWithKeyEtype(username, realm, key, 0, krb5conf, settings...)
}

// NewWithKeyEtype creates a new client from a user's AES Key together with the
// etype id the key belongs to. Use this for the RFC 8009 SHA-2 variants
// (aes128-cts-hmac-sha256-128 / aes256-cts-hmac-sha384-192), which share key
// lengths with their RFC 3962 SHA-1 counterparts and so cannot be inferred
// from length alone.
func NewWithKeyEtype(username, realm string, key []byte, eid int32, krb5conf *config.Config, settings ...func(*Settings)) (*Client, error) {
	creds := credentials.New(username, realm)
	aliases := newClientAliases(krb5conf)
	c := &Client{
		Config:   krb5conf,
		settings: NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
			aliases: aliases,
		},
		cache:   NewCache(),
		aliases: aliases,
	}
	if len(key) != 16 && len(key) != 32 {
		log.Debugf("Invalid AES key length of %d bytes\n", len(key))
		return nil, fmt.Errorf("invalid AES key provided for new client")
	}
	c.Credentials = creds.WithAESKeyEtype(key, eid)

	return c, nil
}

// NewWithPFX creates a new client from a PFX (PKCS#12) certificate file for PKINIT authentication.
func NewWithPFX(username, realm string, pfxData []byte, pfxPass string, krb5conf *config.Config, settings ...func(*Settings)) (*Client, error) {
	creds := credentials.New(username, realm)
	aliases := newClientAliases(krb5conf)
	return &Client{
		Credentials: creds.WithPFX(pfxData, pfxPass),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
			aliases: aliases,
		},
		cache:   NewCache(),
		aliases: aliases,
	}, nil
}

// NewWithKeytab creates a new client from a keytab credential.
// Leave username and/or realm empty to derive them from the keytab's first
// entry; non-empty values override the derived ones (e.g. to pin a realm).
func NewWithKeytab(username, realm string, kt *keytab.Keytab, krb5conf *config.Config, settings ...func(*Settings)) (*Client, error) {
	var creds *credentials.Credentials
	if username == "" || realm == "" {
		if kt == nil {
			return nil, fmt.Errorf("cannot derive principal from a nil keytab")
		}
		pname, krealm, err := kt.Principal()
		if err != nil {
			return nil, err
		}
		if realm == "" {
			realm = krealm
		}
		if username == "" {
			creds = credentials.NewFromPrincipalName(pname, realm) // exact (possibly multi-component) cname
		} else {
			creds = credentials.New(username, realm)
		}
	} else {
		creds = credentials.New(username, realm)
	}
	aliases := newClientAliases(krb5conf)
	return &Client{
		Credentials: creds.WithKeytab(kt),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
			aliases: aliases,
		},
		cache:   NewCache(),
		aliases: aliases,
	}, nil
}

// NewFromCCache create a client from a populated client cache.
//
// WARNING: A client created from CCache does not automatically renew TGTs and a failure will occur after the TGT expires.
func NewFromCCache(c *credentials.CCache, target []string, krb5conf *config.Config, settings ...func(*Settings)) (*Client, error) {
	var targets [][]string
	if target != nil {
		targets = [][]string{target}
	}
	cl, _, err := NewFromCCacheWithFallbacks(c, targets, krb5conf, settings...)
	return cl, err
}

// NewFromCCacheWithFallbacks creates a client from a populated ccache, trying each
// target SPN in order and using the first one with a matching cached service ticket.
// This supports callers that accept multiple equivalent SPNs — e.g. AD's sPNMappings
// where a cached "host/<target>" ticket can satisfy a request for "cifs/<target>",
// "ldap/<target>", etc.
//
// All targets must share the same hostname (target[1]); only the service prefix
// should differ. Referral-ticket handling uses targets[0] as the reference.
//
// Returns the matched target (nil if no service ticket matched but the client was
// successfully created from a TGT or referral ticket) alongside the client.
//
// WARNING: A client created from CCache does not automatically renew TGTs and a failure will occur after the TGT expires.
func NewFromCCacheWithFallbacks(c *credentials.CCache, targets [][]string, krb5conf *config.Config, settings ...func(*Settings)) (*Client, []string, error) {
	var err error
	var foundST, foundTGT, foundReferralTGT, foundOtherReferralTicket bool
	var matchedTarget []string
	var krbReferralSpn types.PrincipalName
	aliases := newClientAliases(krb5conf)
	cl := &Client{
		Credentials: c.GetClientCredentials(),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
			aliases: aliases,
		},
		cache:   NewCache(),
		aliases: aliases,
	}

	// Fallback handling requires at least 2 part SPNs, but primary SPNs could be of another format
	if len(targets) > 1 {
		// Validate every fallback candidate target up front.
		for _, t := range targets[1:] {
			if len(t) < 2 {
				return nil, nil, fmt.Errorf("invalid fallback SPN. A SPN must contain a service and a FQDN or Netbios name")
			}
		}
	}
	// Use targets[0] as the reference for referral-ticket lookup (all candidates
	// share the same hostname — only the service prefix differs).
	var referenceTarget []string
	if len(targets) > 0 {
		referenceTarget = targets[0]
	}
	// Check if we are targeting a referral ticket, and if it already exists in the ccache.
	if referenceTarget != nil {
		if strings.EqualFold(referenceTarget[0], "krbtgt") {
			if !strings.EqualFold(c.DefaultPrincipal.Realm, referenceTarget[1]) {
				// Target realm is not same as client realm so we need a referral ticket
				krbReferralSpn = types.PrincipalName{
					NameType:   nametype.KRB_NT_SRV_INST,
					NameString: []string{"krbtgt", strings.ToUpper(referenceTarget[1])},
				}
				log.Debugf("Trying to find a referral ticket for krbtgt/%s\n", krbReferralSpn.NameString[1])
			}
		} else {
			parts := strings.SplitN(referenceTarget[1], ".", 2)
			// When we are targeting a cross-realm SPN, check if we already have a referral ticket
			if len(parts) > 1 && !strings.EqualFold(c.DefaultPrincipal.Realm, parts[1]) {
				krbReferralSpn = types.PrincipalName{
					NameType:   nametype.KRB_NT_SRV_INST,
					NameString: []string{"krbtgt", strings.ToUpper(parts[1])},
				}
				log.Debugf("Trying to find a referral ticket for krbtgt/%s\n", krbReferralSpn.NameString[1])
			}
		}
		var credReferral *credentials.Credential
		if len(krbReferralSpn.NameString) != 0 {
			credReferral, foundReferralTGT = c.GetEntry(krbReferralSpn)
			if foundReferralTGT {
				var tgt messages.Ticket
				err = tgt.Unmarshal(credReferral.Ticket)
				if err != nil {
					return cl, nil, fmt.Errorf("TGT bytes in cache are not valid: %v", err)
				}
				referralRealm := credReferral.Server.PrincipalName.NameString[1]
				cl.sessions.update(&session{
					realm:      referralRealm,
					authTime:   credReferral.AuthTime,
					endTime:    credReferral.EndTime,
					renewTill:  credReferral.RenewTill,
					tgt:        tgt,
					sessionKey: credReferral.Key,
					flags:      credReferral.TicketFlags,
					cAddr:      credReferral.Addresses,
				})
				log.Debugf("Found referral TGT in ccache and adding it to the session for realm: %s\n", referralRealm)
			}
		}
	}

	krbSpn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", c.DefaultPrincipal.Realm},
	}
	/*
		A ccache could contain a TGT for our realm, a service ticket for our realm,
		a referral ticket e.g., a service ticket for another realms krbtgt service,
		or a service ticket for another realm where the service is not krbtgt.
		For a referral ticket, the fqdn of the SPN will be a realm.
		For a service ticket for another realm, the fqdn in the realm will include
		a hostname.
	*/
	// Walk candidate targets and stop at the first cached service ticket.
	for _, t := range targets {
		spn := types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: t,
		}
		if _, ok := c.GetEntry(spn); ok {
			foundST = true
			matchedTarget = t
			log.Debugf("Found service ticket for %v\n", matchedTarget)
			break
		}
	}
	// Load all referral tickets (krbtgt for foreign realms) as sessions
	for _, cred := range c.GetEntries() {
		// A krbtgt referral entry is "krbtgt/REALM" (2 components). Require at least
		// two before indexing [0]/[1]: a CCache is file input and may carry a
		// principal with too few name components.
		if len(cred.Server.PrincipalName.NameString) >= 2 && strings.EqualFold(cred.Server.PrincipalName.NameString[0], "krbtgt") && !strings.EqualFold(cred.Server.Realm, c.DefaultPrincipal.Realm) {
			foundOtherReferralTicket = true
			var tgt messages.Ticket
			err = tgt.Unmarshal(cred.Ticket)
			if err != nil {
				return cl, nil, fmt.Errorf("Referral ticket bytes in cache are not valid: %v", err)
			}
			referralRealm := cred.Server.PrincipalName.NameString[1]
			cl.sessions.update(&session{
				realm:      referralRealm,
				authTime:   cred.AuthTime,
				endTime:    cred.EndTime,
				renewTill:  cred.RenewTill,
				tgt:        tgt,
				sessionKey: cred.Key,
				flags:      cred.TicketFlags,
				cAddr:      cred.Addresses,
			})
			log.Debugf("Adding TGT to session for realm: %s\n", referralRealm)
		}
	}
	// Locate a TGT for the principal's own realm. The lookup proceeds in
	// three stages, each more speculative than the last:
	//
	//   1. Exact-string krbtgt/<DefaultPrincipal.Realm> hit — the common case.
	//   2. Any krbtgt/<X> in the cache whose realm X is alias-equivalent to
	//      the default principal's realm under the current alias table
	//      (which already includes anything from the [realm_aliases] config
	//      section). This covers BOTH directions of the DNS / NetBIOS
	//      mismatch and any other explicitly declared equivalence.
	//   3. As a last resort, the AD-specific "X is the first DNS label of
	//      the principal's realm" heuristic, kept for callers who have
	//      neither declared aliases up front nor a CCache produced by a KDC
	//      that records both forms.
	cred, foundTGT := c.GetEntry(krbSpn)
	if !foundTGT {
		for _, candidate := range c.GetEntries() {
			ns := candidate.Server.PrincipalName.NameString
			if len(ns) < 2 || !strings.EqualFold(ns[0], "krbtgt") {
				continue
			}
			if cl.IsSameRealm(ns[1], c.DefaultPrincipal.Realm) {
				cred = candidate
				foundTGT = true
				log.Debugf("matched krbtgt entry by alias-equivalent realm: %q ≡ %q\n", ns[1], c.DefaultPrincipal.Realm)
				break
			}
		}
	}
	if !foundTGT {
		// Speculative AD-specific fallback. Try both directions of the
		// "NetBIOS short form == first DNS label of the long form"
		// convention. This is reached only when no exact match and no
		// declared/learned alias produced a hit; the post-match block
		// below records the alias once we've confirmed the entry is usable.

		// (a) short-to-long: principal realm is the long form, cache uses
		//     the short form (krbtgt/CORP for CORP.EXAMPLE.COM).
		krbSpn2 := types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: []string{"krbtgt", strings.Split(c.DefaultPrincipal.Realm, ".")[0]},
		}
		cred, foundTGT = c.GetEntry(krbSpn2)
		if foundTGT {
			log.Debugf("matched krbtgt by short-form fallback heuristic for %q\n", krbSpn2.NameString[1])
		}

		// (b) long-to-short: principal realm is the short form (no dot),
		//     cache uses the long form. Scan for any krbtgt whose first
		//     DNS label equals the default realm.
		if !foundTGT && !strings.Contains(c.DefaultPrincipal.Realm, ".") {
			for _, candidate := range c.GetEntries() {
				ns := candidate.Server.PrincipalName.NameString
				if len(ns) < 2 || !strings.EqualFold(ns[0], "krbtgt") {
					continue
				}
				label := strings.Split(ns[1], ".")[0]
				if strings.EqualFold(label, c.DefaultPrincipal.Realm) {
					cred = candidate
					foundTGT = true
					log.Debugf("matched krbtgt by long-form fallback heuristic: %q starts with %q\n", ns[1], c.DefaultPrincipal.Realm)
					break
				}
			}
		}
	}
	if !foundTGT && !foundST && !foundReferralTGT && !foundOtherReferralTicket {
		return cl, nil, errors.New("No usable TGT or ST found in CCache")
	}
	if foundTGT {
		var tgt messages.Ticket
		err = tgt.Unmarshal(cred.Ticket)
		if err != nil {
			return cl, nil, fmt.Errorf("TGT bytes in cache are not valid: %v", err)
		}
		// If the matched krbtgt entry uses a different realm name than the
		// principal's own (typically the AD NetBIOS short form vs. the DNS
		// long form), record the equivalence so later lookups for either
		// form find this session. The pairing is taken from the CCache the
		// caller provided, not synthesised from string surgery — it's the
		// strongest evidence available at this point.
		matchedRealm := cred.Server.PrincipalName.NameString[1]
		if !config.EqualRealm(matchedRealm, c.DefaultPrincipal.Realm) {
			cl.aliases.Add(matchedRealm, c.DefaultPrincipal.Realm)
			log.Debugf("registered realm alias %q -> %q from CCache krbtgt entry\n", matchedRealm, c.DefaultPrincipal.Realm)
		}
		cl.sessions.update(&session{
			realm:      c.DefaultPrincipal.Realm,
			authTime:   cred.AuthTime,
			endTime:    cred.EndTime,
			renewTill:  cred.RenewTill,
			tgt:        tgt,
			sessionKey: cred.Key,
			flags:      cred.TicketFlags,
			cAddr:      cred.Addresses,
		})
		log.Debugf("Adding TGT to session for default realm: %s\n", c.DefaultPrincipal.Realm)
	}
	for _, cred := range c.GetEntries() {
		var tkt messages.Ticket
		err = tkt.Unmarshal(cred.Ticket)
		if err != nil {
			return cl, nil, fmt.Errorf("cache entry ticket bytes are not valid: %v", err)
		}
		cl.cache.addEntry(
			tkt,
			cred.AuthTime,
			cred.StartTime,
			cred.EndTime,
			cred.RenewTill,
			cred.Key,
			cred.TicketFlags,
		)
		log.Debugf("Adding service ticket to session for SPN: %s\n", cred.Server.PrincipalName.PrincipalNameString())
	}
	return cl, matchedTarget, nil
}

func NewFromTicket(c *credentials.Credential, krb5conf *config.Config, settings ...func(*Settings)) (*Client, error) {
	aliases := newClientAliases(krb5conf)
	cl := &Client{
		Credentials: credentials.New(c.Client.PrincipalName.PrincipalNameString(), c.Client.Realm),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
			aliases: aliases,
		},
		cache:   NewCache(),
		aliases: aliases,
	}
	err := cl.AddTicketToSession(c, "")
	if err != nil {
		return nil, err
	}
	return cl, nil
}

func (cl *Client) AddTicketToSession(c *credentials.Credential, realm string) error {
	var tgt messages.Ticket
	err := tgt.Unmarshal(c.Ticket)
	if err != nil {
		return fmt.Errorf("TGT bytes in cache are not valid: %v", err)
	}

	// Route through sessions.update so the map key goes through realmKey
	// (alias-aware canonicalisation) and the write takes the sessions mutex.
	// The previous direct write to sessions.Entries[realm] bypassed both and
	// raced concurrent renewals.
	sessRealm := realm
	if sessRealm == "" {
		sessRealm = c.Client.Realm
	}
	cl.sessions.update(&session{
		realm:      sessRealm,
		authTime:   c.AuthTime,
		endTime:    c.EndTime,
		renewTill:  c.RenewTill,
		tgt:        tgt,
		sessionKey: c.Key,
		flags:      c.TicketFlags,
		cAddr:      c.Addresses,
	})

	return nil
}

// IsSameRealm reports whether two realm-name strings refer to the same realm.
// Comparison is by canonical form (trailing dot trimmed, ASCII uppercased)
// and consults the client's runtime alias table, so e.g. "CORP" and
// "CORP.EXAMPLE.COM" compare equal once they have been recorded via
// AddRealmAlias.
//
// All Client constructors populate cl.aliases via newClientAliases. The nil
// branch only matters for callers that build a Client by struct literal —
// it falls back to canonical-form equality with no alias resolution.
func (cl *Client) IsSameRealm(a, b string) bool {
	if cl.aliases == nil {
		return config.EqualRealm(a, b)
	}
	return cl.aliases.Resolve(a) == cl.aliases.Resolve(b)
}

// AddRealmAlias records a realm-name equivalence on the client. Use this
// when calling code knows that two strings name the same realm in the
// deployment (most commonly a NetBIOS short name and its DNS-style long
// name). The canonical argument is the form returned by IsSameRealm and by
// RealmAliases().Resolve().
func (cl *Client) AddRealmAlias(alias, canonical string) {
	cl.aliases.Add(alias, canonical)
}

// RealmAliases returns the client's runtime alias table. It is safe for
// concurrent use.
func (cl *Client) RealmAliases() *config.RealmAliases {
	return cl.aliases
}

// AddCacheEntries create populates an existing cache with new tickets
func (cl *Client) AddCacheEntries(c *credentials.CCache) error {
	var err error
	for _, cred := range c.GetEntries() {
		var tkt messages.Ticket
		err = tkt.Unmarshal(cred.Ticket)
		if err != nil {
			return fmt.Errorf("cache entry ticket bytes are not valid: %v", err)
		}
		cl.cache.addEntry(
			tkt,
			cred.AuthTime,
			cred.StartTime,
			cred.EndTime,
			cred.RenewTill,
			cred.Key,
			cred.TicketFlags,
		)
	}
	return nil
}

// Key returns the client's encryption key for the specified encryption type and its kvno (kvno of zero will find latest).
// The key can be retrieved either from the keytab or generated from the client's password.
// If the client has both a keytab and a password defined the keytab is favoured as the source for the key
// A KRBError can be passed in the event the KDC returns one of type KDC_ERR_PREAUTH_REQUIRED and is required to derive
// the key for pre-authentication from the client's password. If a KRBError is not available, pass nil to this argument.
func (cl *Client) Key(et etype.EType, kvno int, krberr *messages.KRBError) (types.EncryptionKey, int, error) {
	var err error
	if cl.Credentials.HasKeytab() && et != nil {
		return cl.Credentials.Keytab().GetEncryptionKey(cl.Credentials.CName(), cl.Credentials.Domain(), kvno, et.GetETypeID())
	} else if cl.Credentials.HasPassword() {
		if krberr != nil && krberr.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED {
			var pas types.PADataSequence
			err := pas.Unmarshal(krberr.EData)
			if err != nil {
				return types.EncryptionKey{}, 0, fmt.Errorf("could not get PAData from KRBError to generate key from password: %v", err)
			}
			key, _, err := crypto.GetKeyFromPassword(cl.Credentials.Password(), krberr.CName, krberr.CRealm, et.GetETypeID(), pas)
			return key, 0, err
		}
		key, _, err := crypto.GetKeyFromPassword(cl.Credentials.Password(), cl.Credentials.CName(), cl.Credentials.Domain(), et.GetETypeID(), types.PADataSequence{})
		return key, 0, err
	} else if cl.Credentials.HasNTHash() {
		et, err = crypto.GetEtype(etypeID.RC4_HMAC)
		if err != nil {
			return types.EncryptionKey{}, 0, err
		}
		if krberr != nil && krberr.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED {
			var pas types.PADataSequence
			err := pas.Unmarshal(krberr.EData)
			if err != nil {
				return types.EncryptionKey{}, 0, fmt.Errorf("could not get PAData from KRBError to generate key from NT Hash: %v", err)
			}
			key, _, err := crypto.GetKeyFromHash(cl.Credentials.NTHash(), krberr.CName, krberr.CRealm, et.GetETypeID(), pas)
			return key, 0, err
		}
		key, _, err := crypto.GetKeyFromHash(cl.Credentials.NTHash(), cl.Credentials.CName(), cl.Credentials.Domain(), et.GetETypeID(), types.PADataSequence{})
		return key, 0, err
	} else if cl.Credentials.HasAESKey() {
		if eid := cl.Credentials.AESKeyEtype(); eid != 0 {
			et, err = crypto.GetEtype(eid)
		} else if len(cl.Credentials.AESKey()) == 32 {
			et, err = crypto.GetEtype(etypeID.AES256_CTS_HMAC_SHA1_96)
		} else {
			et, err = crypto.GetEtype(etypeID.AES128_CTS_HMAC_SHA1_96)
		}
		if err != nil {
			return types.EncryptionKey{}, 0, err
		}
		if krberr != nil && krberr.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED {
			var pas types.PADataSequence
			err := pas.Unmarshal(krberr.EData)
			if err != nil {
				return types.EncryptionKey{}, 0, fmt.Errorf("could not get PAData from KRBError to generate key from AES Hash: %v", err)
			}
			key, _, err := crypto.GetKeyFromHash(cl.Credentials.AESKey(), krberr.CName, krberr.CRealm, et.GetETypeID(), pas)
			return key, 0, err
		}
		key, _, err := crypto.GetKeyFromHash(cl.Credentials.AESKey(), cl.Credentials.CName(), cl.Credentials.Domain(), et.GetETypeID(), types.PADataSequence{})
		return key, 0, err
	}
	return types.EncryptionKey{}, 0, errors.New("credential has neither keytab, password, or hash to generate key")
}

// IsConfigured indicates if the client has the values required set.
func (cl *Client) IsConfigured() (bool, error) {
	if cl.Credentials.UserName() == "" {
		return false, errors.New("client does not have a username")
	}
	if cl.Credentials.Domain() == "" {
		return false, errors.New("client does not have a define realm")
	}
	// Client needs to have either a password, keytab or a session already (later when loading from CCache)
	if !cl.Credentials.HasPassword() && !cl.Credentials.HasKeytab() && !cl.Credentials.HasNTHash() && !cl.Credentials.HasAESKey() && !cl.Credentials.HasPFX() {
		authTime, _, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
		if err != nil || authTime.IsZero() {
			return false, errors.New("client has neither a keytab nor a password nor a password hash nor a PFX certificate set and no session")
		}
	}
	if !cl.Config.LibDefaults.DNSLookupKDC {
		for _, r := range cl.Config.Realms {
			if r.Realm == cl.Credentials.Domain() {
				if len(r.KDC) > 0 {
					return true, nil
				}
				return false, errors.New("client krb5 config does not have any defined KDCs for the default realm")
			}
		}
	}
	return true, nil
}

// Login the client with the KDC via an AS exchange.
func (cl *Client) Login() error {

	if ok, err := cl.IsConfigured(); !ok {
		return err
	}
	if !cl.Credentials.HasPassword() && !cl.Credentials.HasKeytab() && !cl.Credentials.HasNTHash() && !cl.Credentials.HasAESKey() && !cl.Credentials.HasPFX() {
		_, endTime, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
		if err != nil {
			return krberror.Errorf(err, krberror.KRBMsgError, "no user credentials available and error getting any existing session")
		}
		if time.Now().UTC().After(endTime) {
			return krberror.New(krberror.KRBMsgError, "cannot login, no user credentials available and no valid existing session")
		}
		// no credentials but there is a session with tgt already
		return nil
	}
	ASReq, err := messages.NewASReqForTGT(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "error generating new AS_REQ")
	}
	// When logging in from a keytab, constrain the requested etypes to those the
	// keytab actually holds a key for. The KDC derives both the pre-auth
	// ETYPE-INFO2 hint and the AS-REP reply key from the request's etype list, so
	// offering an etype we cannot key (e.g. AES256 when the keytab only holds
	// AES128) makes pre-authentication and/or AS-REP decryption fail.
	if etypes := cl.keytabRequestEtypes(); len(etypes) > 0 {
		ASReq.ReqBody.EType = etypes
	}
	ASRep, err := cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
	if err != nil {
		return err
	}
	cl.addSession(ASRep.Ticket, ASRep.DecryptedEncPart)
	return nil
}

// keytabRequestEtypes returns the configured default_tkt_enctypes filtered to the
// etypes for which the client's keytab holds a key for the login principal,
// preserving the configured preference order. It returns nil when the client has
// no keytab or no configured etype matches a keytab key (in which case callers
// should leave the AS-REQ etype list untouched rather than empty it).
func (cl *Client) keytabRequestEtypes() []int32 {
	if !cl.Credentials.HasKeytab() {
		return nil
	}
	kt := cl.Credentials.Keytab()
	cname := cl.Credentials.CName()
	realm := cl.Credentials.Domain()
	var out []int32
	for _, et := range cl.Config.LibDefaults.DefaultTktEnctypeIDs {
		if _, _, err := kt.GetEncryptionKey(cname, realm, 0, et); err == nil {
			out = append(out, et)
		}
	}
	return out
}

// AffirmLogin will only perform an AS exchange with the KDC if the client does not already have a TGT.
func (cl *Client) AffirmLogin() error {
	_, endTime, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
	if err != nil || time.Now().UTC().After(endTime) {
		err := cl.Login()
		if err != nil {
			return fmt.Errorf("could not get valid TGT for client's realm: %v", err)
		}
	}
	return nil
}

// realmLogin obtains or renews a TGT and establishes a session for the realm specified.
func (cl *Client) realmLogin(realm string) error {
	// Compare via the alias table: callers may pass either form of a realm
	// that aliases the client's own (e.g. NetBIOS "CORP" vs DNS
	// "CORP.EXAMPLE.COM"). Raw string equality here would push the
	// alias-equivalent case down the cross-realm referral path, asking the
	// home KDC for krbtgt/<other-form>@<home-form>.
	if cl.IsSameRealm(realm, cl.Credentials.Domain()) {
		return cl.Login()
	}
	_, endTime, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
	if err != nil || time.Now().UTC().After(endTime) {
		err := cl.Login()
		if err != nil {
			return fmt.Errorf("could not get valid TGT for client's realm: %v", err)
		}
	}
	tgt, skey, err := cl.sessionTGT(cl.Credentials.Domain())
	if err != nil {
		return err
	}

	// Handle referral ticket
	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}

	_, tgsRep, err := cl.TGSREQGenerateAndExchange(spn, cl.Credentials.Domain(), tgt, skey, false)
	if err != nil {
		return err
	}
	cl.addSession(tgsRep.Ticket, tgsRep.DecryptedEncPart)

	return nil
}

// Destroy stops the auto-renewal of all sessions and removes the sessions and cache entries from the client.
func (cl *Client) Destroy() {
	creds := credentials.New("", "")
	cl.sessions.destroy()
	cl.cache.clear()
	cl.Credentials = creds
	cl.Log("client destroyed")
}

// Diagnostics runs a set of checks that the client is properly configured and writes details to the io.Writer provided.
func (cl *Client) Diagnostics(w io.Writer) error {
	cl.Print(w)
	var errs []string
	if cl.Credentials.HasKeytab() {
		var loginRealmEncTypes []int32
		for _, e := range cl.Credentials.Keytab().Entries {
			if e.Principal.Realm == cl.Credentials.Realm() {
				loginRealmEncTypes = append(loginRealmEncTypes, e.Key.KeyType)
			}
		}
		for _, et := range cl.Config.LibDefaults.DefaultTktEnctypeIDs {
			var etInKt bool
			for _, val := range loginRealmEncTypes {
				if val == et {
					etInKt = true
					break
				}
			}
			if !etInKt {
				errs = append(errs, fmt.Sprintf("default_tkt_enctypes specifies %d but this enctype is not available in the client's keytab", et))
			}
		}
		for _, et := range cl.Config.LibDefaults.PreferredPreauthTypes {
			var etInKt bool
			for _, val := range loginRealmEncTypes {
				if int(val) == et {
					etInKt = true
					break
				}
			}
			if !etInKt {
				errs = append(errs, fmt.Sprintf("preferred_preauth_types specifies %d but this enctype is not available in the client's keytab", et))
			}
		}
	}
	udpCnt, udpKDC, err := cl.Config.GetKDCs(cl.Credentials.Realm(), false)
	if err != nil {
		errs = append(errs, fmt.Sprintf("error when resolving KDCs for UDP communication: %v", err))
	}
	if udpCnt < 1 {
		errs = append(errs, "no KDCs resolved for communication via UDP.")
	} else {
		b, _ := json.MarshalIndent(&udpKDC, "", "  ")
		fmt.Fprintf(w, "UDP KDCs: %s\n", string(b))
	}
	tcpCnt, tcpKDC, err := cl.Config.GetKDCs(cl.Credentials.Realm(), false)
	if err != nil {
		errs = append(errs, fmt.Sprintf("error when resolving KDCs for TCP communication: %v", err))
	}
	if tcpCnt < 1 {
		errs = append(errs, "no KDCs resolved for communication via TCP.")
	} else {
		b, _ := json.MarshalIndent(&tcpKDC, "", "  ")
		fmt.Fprintf(w, "TCP KDCs: %s\n", string(b))
	}

	if errs == nil || len(errs) < 1 {
		return nil
	}
	return errors.New(strings.Join(errs, "\n"))
}

// Print writes the details of the client to the io.Writer provided.
func (cl *Client) Print(w io.Writer) {
	c, _ := cl.Credentials.JSON()
	fmt.Fprintf(w, "Credentials:\n%s\n", c)

	s, _ := cl.sessions.JSON()
	fmt.Fprintf(w, "TGT Sessions:\n%s\n", s)

	c, _ = cl.cache.JSON()
	fmt.Fprintf(w, "Service ticket cache:\n%s\n", c)

	s, _ = cl.settings.JSON()
	fmt.Fprintf(w, "Settings:\n%s\n", s)

	j, _ := cl.Config.JSON()
	fmt.Fprintf(w, "Krb5 config:\n%s\n", j)

	k, _ := cl.Credentials.Keytab().JSON()
	fmt.Fprintf(w, "Keytab:\n%s\n", k)
}

func (cl *Client) GetTGT(domain string) (tgt messages.Ticket, sessionKey types.EncryptionKey, err error) {
	return cl.sessionTGT(domain)
}

func (cl *Client) addTGTToCCache(cache *credentials.CCache, clientPrincipal types.PrincipalName, clientRealm string) (err error) {
	var flags asn1.BitString
	clientRealm = strings.ToUpper(clientRealm)
	if clientRealm == "" {
		clientRealm = cl.Credentials.Realm()
	}
	principal := credentials.NewPrincipal(clientPrincipal, clientRealm)
	var cAddr []types.HostAddress
	flags, cAddr, err = cl.sessionTGTDetails(clientRealm)
	if err != nil {
		return
	}
	var tgt messages.Ticket
	var sessionKey types.EncryptionKey
	tgt, sessionKey, err = cl.sessionTGT(clientRealm)
	if err != nil {
		return
	}
	var authTime, endTime, renewTime time.Time
	authTime, endTime, renewTime, _, err = cl.sessionTimes(clientRealm)
	if err != nil {
		return
	}
	var tgtBytes []byte
	kdcPrincipal := credentials.NewPrincipal(tgt.SName, tgt.Realm)
	tgtBytes, err = tgt.Marshal()
	if err != nil {
		return
	}
	credTGT := &credentials.Credential{
		Client:      principal,
		Server:      kdcPrincipal,
		Key:         sessionKey,
		AuthTime:    authTime,
		StartTime:   authTime,
		EndTime:     endTime,
		RenewTill:   renewTime,
		TicketFlags: flags,
		Addresses:   cAddr,
		Ticket:      tgtBytes,
	}
	cache.AddCredential(credTGT)
	return
}

func (cl *Client) SaveAllTicketsToCCache(ccache *credentials.CCache, clientPrincipal types.PrincipalName, clientRealm string) (err error) {
	err = cl.addTGTToCCache(ccache, clientPrincipal, clientRealm)
	if err != nil {
		fmt.Printf("Couldn't save session TGT for userDomain: %s because: %s\n", clientRealm, err.Error())
	}
	entries := cl.cache.getEntries()
	for _, entry := range entries {
		// Skip the local-realm TGT; service tickets only are saved here. The
		// comparison is case-insensitive because entry.SPN preserves the KDC's
		// canonical form, which may differ in case from cl.Credentials.Realm().
		if strings.EqualFold(entry.SPN, "krbtgt/"+cl.Credentials.Realm()) {
			continue
		}
		if ccache.Contains(entry.Ticket.SName) {
			// Skip since already in the ccache
			continue
		}
		var ticketBytes []byte
		server := credentials.NewPrincipal(entry.Ticket.SName, entry.Ticket.Realm)
		ticketBytes, err = entry.Ticket.Marshal()
		if err != nil {
			return
		}

		cred := &credentials.Credential{
			Client:      credentials.NewPrincipal(clientPrincipal, clientRealm),
			Server:      server,
			Key:         entry.SessionKey,
			AuthTime:    entry.AuthTime,
			StartTime:   entry.StartTime,
			EndTime:     entry.EndTime,
			RenewTill:   entry.RenewTill,
			TicketFlags: entry.Flags,
			Ticket:      ticketBytes,
		}
		ccache.AddCredential(cred)
	}
	return
}

func (cl *Client) SaveSPNToCCache(ccache *credentials.CCache, clientPrincipal types.PrincipalName, clientRealm, spn, altService string) (err error) {
	var ticketBytes []byte
	var cred *credentials.Credential
	principal := credentials.NewPrincipal(clientPrincipal, clientRealm)

	parts := strings.Split(spn, "/")
	if strings.EqualFold(parts[0], "krbtgt") {
		if len(parts) != 2 {
			return fmt.Errorf("Invalid SPN for krbtgt: expected krbtgt/REALM")
		}
		var tgt messages.Ticket
		var sessionKey types.EncryptionKey
		var flags asn1.BitString
		var cAddr []types.HostAddress
		tgt, sessionKey, err = cl.GetTGT(parts[1])
		if err != nil {
			return err
		}
		flags, cAddr, err = cl.sessionTGTDetails(parts[1])
		if err != nil {
			return
		}
		var authTime, endTime, renewTime time.Time
		authTime, endTime, renewTime, _, err = cl.sessionTimes(cl.Credentials.Realm())
		if err != nil {
			return
		}
		var tgtBytes []byte
		kdcPrincipal := credentials.NewPrincipal(tgt.SName, tgt.Realm)
		tgtBytes, err = tgt.Marshal()
		if err != nil {
			return
		}

		cred = &credentials.Credential{
			Client:      principal,
			Server:      kdcPrincipal,
			Key:         sessionKey,
			AuthTime:    authTime,
			StartTime:   authTime,
			EndTime:     endTime,
			RenewTill:   renewTime,
			TicketFlags: flags,
			Addresses:   cAddr,
			Ticket:      tgtBytes,
		}
	} else {
		entry, found := cl.cache.getEntry(spn)
		if !found {
			err = fmt.Errorf("Service Ticket not found in cache with SPN: %s", spn)
			return
		}
		server := credentials.NewPrincipal(entry.Ticket.SName, entry.Ticket.Realm)
		if altService != "" {
			newSPN := ""
			if strings.Contains(altService, "/") {
				newSPN = altService
			} else if len(parts) > 1 {
				newSPN = altService + "/" + parts[1]
			} else {
				newSPN = altService
			}
			// Replace Sname in ticket for spn
			server.PrincipalName = types.NewPrincipalName(nametype.KRB_NT_SRV_INST, newSPN)
			entry.Ticket.SName = server.PrincipalName
		}

		ticketBytes, err = entry.Ticket.Marshal()
		if err != nil {
			return
		}
		cred = &credentials.Credential{
			Client:      principal,
			Server:      server,
			Key:         entry.SessionKey,
			AuthTime:    entry.AuthTime,
			StartTime:   entry.StartTime,
			EndTime:     entry.EndTime,
			RenewTill:   entry.RenewTill,
			TicketFlags: entry.Flags,
			Ticket:      ticketBytes,
		}
	}
	ccache.AddCredential(cred)
	return nil
}
