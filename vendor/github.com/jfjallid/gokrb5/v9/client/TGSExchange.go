package client

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/jfjallid/gokrb5/v9/config"
	"github.com/jfjallid/gokrb5/v9/iana/flags"
	"github.com/jfjallid/gokrb5/v9/iana/nametype"
	"github.com/jfjallid/gokrb5/v9/krberror"
	"github.com/jfjallid/gokrb5/v9/messages"
	"github.com/jfjallid/gokrb5/v9/types"
)

// TGSREQGenerateAndExchange generates the TGS_REQ and performs a TGS exchange to retrieve a ticket to the specified SPN.
func (cl *Client) TGSREQGenerateAndExchange(spn types.PrincipalName, kdcRealm string, tgt messages.Ticket, sessionKey types.EncryptionKey, renewal bool) (tgsReq messages.TGSReq, tgsRep messages.TGSRep, err error) {
	tgsReq, err = messages.NewTGSReq(cl.Credentials.CName(), cl.Credentials.Domain(), kdcRealm, cl.Config, tgt, sessionKey, spn, renewal)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.KRBMsgError, "TGS Exchange Error: failed to generate a new TGS_REQ")
	}
	return cl.TGSExchange(tgsReq, kdcRealm, tgsRep.Ticket, sessionKey, 0)
}

// TGSExchange exchanges the provided TGS_REQ with the KDC to retrieve a TGS_REP.
// Referrals are automatically handled.
// The client's cache is updated with the ticket received.
func (cl *Client) TGSExchange(tgsReq messages.TGSReq, kdcRealm string, tgt messages.Ticket, sessionKey types.EncryptionKey, referral int) (messages.TGSReq, messages.TGSRep, error) {
	var tgsRep messages.TGSRep
	b, err := tgsReq.Marshal()
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to marshal TGS_REQ")
	}
	r, err := cl.sendToKDC(b, kdcRealm)
	if err != nil {
		if _, ok := err.(messages.KRBError); ok {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.KDCError, "TGS Exchange Error: kerberos error response from KDC when requesting for %s", tgsReq.ReqBody.SName.PrincipalNameString())
		}
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.NetworkingError, "TGS Exchange Error: issue sending TGS_REQ to KDC")
	}
	err = tgsRep.Unmarshal(r)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to process the TGS_REP")
	}
	err = tgsRep.DecryptEncPart(sessionKey)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to process the TGS_REP")
	}
	if ok, err := tgsRep.Verify(cl.Config, cl.RealmAliases(), tgsReq); !ok {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: TGS_REP is not valid")
	}

	// The krbtgt service name is matched case-insensitively to stay consistent
	// with the request-side check below (strings.EqualFold) and to tolerate a
	// KDC that canonicalises the service name's case. The second clause keeps
	// using Equal: it only fires when both sides are krbtgt, and realm-name
	// equivalence is handled explicitly by the alias registration that follows.
	// SName is cleartext in the reply, so a malformed/tampered TGS_REP could carry
	// an empty NameString; guard the index before the krbtgt referral check.
	if len(tgsRep.Ticket.SName.NameString) > 0 && strings.EqualFold(tgsRep.Ticket.SName.NameString[0], "krbtgt") && !tgsRep.Ticket.SName.Equal(tgsReq.ReqBody.SName) {
		if referral > 5 {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.KRBMsgError, "TGS Exchange Error: maximum number of referrals exceeded")
		}
		// Server referral https://tools.ietf.org/html/rfc6806.html#section-8
		// The TGS Rep contains a TGT for another domain as the service resides in that domain.
		cl.addSession(tgsRep.Ticket, tgsRep.DecryptedEncPart)
		// Also save the referral ticket in the cache
		cl.cache.addEntry(
			tgsRep.Ticket,
			tgsRep.DecryptedEncPart.AuthTime,
			tgsRep.DecryptedEncPart.StartTime,
			tgsRep.DecryptedEncPart.EndTime,
			tgsRep.DecryptedEncPart.RenewTill,
			tgsRep.DecryptedEncPart.Key,
			tgsRep.DecryptedEncPart.Flags,
		)
		realm := tgsRep.Ticket.SName.NameString[len(tgsRep.Ticket.SName.NameString)-1]
		// Form-normalisation aliases: if we requested a krbtgt for realm
		// form A and the KDC handed us a krbtgt for form B (request SName
		// and response SName both krbtgt, with differing realm portions),
		// the KDC is telling us A and B name the same realm. Record the
		// equivalence so subsequent lookups in either form hit the same
		// session. Genuine cross-realm referrals (SPN -> krbtgt) are
		// excluded by the krbtgt-on-both-sides check.
		if len(tgsReq.ReqBody.SName.NameString) >= 2 &&
			strings.EqualFold(tgsReq.ReqBody.SName.NameString[0], "krbtgt") {
			reqRealm := tgsReq.ReqBody.SName.NameString[1]
			if !config.EqualRealm(reqRealm, realm) {
				cl.AddRealmAlias(reqRealm, realm)
				log.Debugf("registered realm alias from TGS referral: %q -> %q\n", reqRealm, realm)
			}
		}
		referral++
		if types.IsFlagSet(&tgsReq.ReqBody.KDCOptions, flags.EncTktInSkey) && len(tgsReq.ReqBody.AdditionalTickets) > 0 {
			tgsReq, err = messages.NewUser2UserTGSReq(cl.Credentials.CName(), kdcRealm, cl.Config, tgt, sessionKey, tgsReq.ReqBody.SName, tgsReq.Renewal, tgsReq.ReqBody.AdditionalTickets[0])
			if err != nil {
				return tgsReq, tgsRep, err
			}
		}
		tgsReq, err = messages.NewTGSReq(cl.Credentials.CName(), cl.Credentials.Domain(), realm, cl.Config, tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, tgsReq.ReqBody.SName, tgsReq.Renewal)
		if err != nil {
			return tgsReq, tgsRep, err
		}
		return cl.TGSExchange(tgsReq, realm, tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, referral)
	}
	cl.cache.addEntry(
		tgsRep.Ticket,
		tgsRep.DecryptedEncPart.AuthTime,
		tgsRep.DecryptedEncPart.StartTime,
		tgsRep.DecryptedEncPart.EndTime,
		tgsRep.DecryptedEncPart.RenewTill,
		tgsRep.DecryptedEncPart.Key,
		tgsRep.DecryptedEncPart.Flags,
	)
	log.Debugf("ticket added to cache for %s (EndTime: %v)\n", tgsRep.Ticket.SName.PrincipalNameString(), tgsRep.DecryptedEncPart.EndTime)
	cl.Log("ticket added to cache for %s (EndTime: %v)", tgsRep.Ticket.SName.PrincipalNameString(), tgsRep.DecryptedEncPart.EndTime)
	return tgsReq, tgsRep, err
}

// GetServiceTicket makes a request to get a service ticket for the SPN specified
// SPN format: <SERVICE>/<FQDN> Eg. HTTP/www.example.com
// The ticket will be added to the client's ticket cache
func (cl *Client) GetServiceTicket(spn string) (messages.Ticket, types.EncryptionKey, error) {
	return cl.GetServiceTicketExt(spn, "")
}

func (cl *Client) GetServiceTicketExt(spn, dcDomain string) (messages.Ticket, types.EncryptionKey, error) {
	var tkt messages.Ticket
	var skey types.EncryptionKey
	log.Debugf("Getting a service ticket for SPN: %s", spn)
	if tkt, skey, ok := cl.GetCachedTicket(spn); ok {
		log.Debugf("Found ticket in cache for SPN: %s", spn)
		// Already a valid ticket in the cache
		return tkt, skey, nil
	}
	// We want to support multiple formats of SPNs so let's try to figure out which Principal name type to use
	serverSPNType := nametype.KRB_NT_UNKNOWN
	if strings.Contains(spn, "/") {
		serverSPNType = nametype.KRB_NT_SRV_INST
	} else {
		// Most flexible type
		serverSPNType = nametype.KRB_NT_ENTERPRISE
	}

	princ := types.NewPrincipalName(serverSPNType, spn)
	realm := cl.resolveTargetRealm(spn, dcDomain)

	tgt, skey, err := cl.sessionTGT(realm)
	if err != nil {
		return tkt, skey, err
	}
	if tgt.SName.Equal(princ) {
		// Found our ticket already!
		return tgt, skey, nil
	}
	_, tgsRep, err := cl.TGSREQGenerateAndExchange(princ, realm, tgt, skey, false)
	if err != nil {
		return tkt, skey, err
	}
	return tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, nil
}

// resolveTargetRealm picks the realm to use when requesting a service
// ticket for spn. The chain proceeds from least-speculative to most:
//
//  1. an explicit dcDomain override (caller knows best);
//  2. for a krbtgt/<R> SPN, the realm is R by definition;
//  3. an entry in the Config's [domain_realm] map for the SPN host or a
//     parent DNS zone (the static, intentional configuration path);
//  4. when Config.LibDefaults.DNSLookupRealm is true, a DNS TXT lookup of
//     _kerberos.<host> walking up the host suffix;
//  5. (legacy) the AD-flavored guess that strips the first DNS label of
//     the host and uses the remainder as the realm — gated by the
//     AllowDomainSuffixRealmGuess setting (default on for back-compat);
//  6. the client's own realm as last resort.
//
// Each successful step is logged at debug level so misconfigurations are
// diagnosable from logs.
func (cl *Client) resolveTargetRealm(spn, dcDomain string) string {
	if dcDomain != "" {
		log.Debugf("realm resolution for %q: using explicit dcDomain %q\n", spn, dcDomain)
		return dcDomain
	}

	parts := strings.Split(spn, "/")
	if len(parts) > 1 && strings.EqualFold(parts[0], "krbtgt") {
		r := strings.ToUpper(parts[1])
		log.Debugf("realm resolution for %q: krbtgt SPN, realm is %q\n", spn, r)
		return r
	}

	var host string
	if len(parts) > 1 {
		host = parts[1]
	} else {
		host = spn
	}

	if r := cl.Config.ResolveRealm(host); r != "" {
		log.Debugf("realm resolution for %q: [domain_realm] entry -> %q\n", spn, r)
		return r
	}

	if cl.Config.LibDefaults.DNSLookupRealm {
		if r := cl.lookupRealmDNS(host); r != "" {
			log.Debugf("realm resolution for %q: DNS TXT lookup -> %q\n", spn, r)
			return r
		}
	}

	if cl.settings.AllowDomainSuffixRealmGuess() {
		if i := strings.Index(host, "."); i > 0 && i < len(host)-1 {
			r := strings.ToUpper(host[i+1:])
			log.Debugf("realm resolution for %q: suffix-strip heuristic -> %q\n", spn, r)
			return r
		}
	}

	r := cl.Credentials.Realm()
	log.Debugf("realm resolution for %q: no match, falling back to client realm %q\n", spn, r)
	return r
}

// lookupRealmDNS resolves a host to a realm via TXT records, walking up the
// host suffix in the same order MIT krb5 does: _kerberos.<host>, then
// _kerberos.<parent>, etc. Returns empty on miss or on any DNS error.
//
// SECURITY: TXT records are unauthenticated DNS data. A spoofed response
// can redirect the client to an attacker-controlled realm. This path is
// only reached when Config.LibDefaults.DNSLookupRealm is true — the same
// caveat applies as in MIT krb5's dns_lookup_realm option.
func (cl *Client) lookupRealmDNS(host string) string {
	if host == "" {
		return ""
	}
	host = strings.TrimSuffix(host, ".")
	timeout := cl.settings.DNSRealmLookupTimeout()
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	resolver := net.DefaultResolver
	for h := host; h != ""; {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		txts, err := resolver.LookupTXT(ctx, "_kerberos."+h)
		cancel()
		if err == nil {
			for _, t := range txts {
				if t = strings.TrimSpace(t); t != "" {
					return t
				}
			}
		}
		i := strings.Index(h, ".")
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	return ""
}
