package config

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/jfjallid/gokrb5/v9/imported/dnsutils/v2"
	"golang.org/x/net/proxy"
)

func (c *Config) SetDNSResolver(dialer proxy.ContextDialer, addr, protocol string) (err error) {
	if dialer == nil {
		err = fmt.Errorf("dialer cannot be empty!")
		return
	}
	parts := strings.Split(addr, ":")
	if len(parts) < 2 {
		fmt.Println("Invalid addr. Format is ip:port")
		return
	}
	ip := net.ParseIP(parts[0])
	if ip == nil {
		fmt.Println("Not a valid ip host address")
		return
	}
	p, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		fmt.Printf("Invalid addr. Failed to parse port: %s\n", err)
		return
	}
	if p < 1 {
		fmt.Println("Invalid port number")
		return
	}

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, protocol, addr)
		},
	}
	return nil
}

// GetKDCs returns the count of KDCs available and a map of KDC host names keyed on preference order.
func (c *Config) GetKDCs(realm string, tcp bool) (int, map[int]string, error) {
	if realm == "" {
		realm = c.LibDefaults.DefaultRealm
	}
	kdcs := make(map[int]string)
	var count int

	// Get the KDCs from the krb5.conf.
	var ks []string
	for _, r := range c.Realms {
		if r.Realm != realm {
			continue
		}
		ks = r.KDC
	}
	count = len(ks)

	// Alias fallback: a caller may name a realm by a form (NetBIOS short
	// name, lower-cased DNS form, …) that does not match the entry in
	// c.Realms verbatim. Walk the equivalents from the alias table and
	// retry with case-insensitive comparison. This is only entered after
	// the strict pass fails, so existing configs keep their behaviour.
	if count == 0 && c.RealmAliases != nil {
		for _, eq := range c.RealmAliases.Equivalents(realm) {
			if strings.EqualFold(eq, realm) {
				continue
			}
			for _, r := range c.Realms {
				if !strings.EqualFold(r.Realm, eq) {
					continue
				}
				ks = r.KDC
			}
			if len(ks) > 0 {
				break
			}
		}
		count = len(ks)
	}

	if count > 0 {
		// Order the kdcs randomly for preference.
		kdcs = randServOrder(ks)
		return count, kdcs, nil
	}

	if !c.LibDefaults.DNSLookupKDC {
		return count, kdcs, fmt.Errorf("no KDCs defined in configuration for realm %s", realm)
	}

	// Use DNS to resolve kerberos SRV records.
	proto := "udp"
	if tcp {
		proto = "tcp"
	}
	index, addrs, err := dnsutils.OrderedSRV("kerberos", proto, realm)
	if err != nil {
		return count, kdcs, err
	}
	if len(addrs) < 1 {
		return count, kdcs, fmt.Errorf("no KDC SRV records found for realm %s", realm)
	}
	count = index
	for k, v := range addrs {
		kdcs[k] = strings.TrimRight(v.Target, ".") + ":" + strconv.Itoa(int(v.Port))
	}
	return count, kdcs, nil
}

// kpasswdServersForRealm returns the kpasswd server addresses configured for
// realm in c.Realms (matched case-insensitively). It prefers an explicit
// kpasswd_server, then admin_server, and finally derives the address from the
// realm's KDC host on the kpasswd port (464) — in Active Directory the DC that
// serves the AS/TGS also serves kpasswd, so this keeps password changes on the
// same host that issued the tickets instead of forcing a separate DNS lookup.
// It returns nil when the realm has no entry or no usable host.
func (c *Config) kpasswdServersForRealm(realm string) []string {
	for _, r := range c.Realms {
		if !strings.EqualFold(r.Realm, realm) {
			continue
		}
		if len(r.KPasswdServer) > 0 {
			return append([]string(nil), r.KPasswdServer...)
		}
		var ks []string
		for _, a := range r.AdminServer {
			ks = append(ks, hostWithKpasswdPort(a))
		}
		if len(ks) > 0 {
			return ks
		}
		for _, k := range r.KDC {
			ks = append(ks, hostWithKpasswdPort(k))
		}
		return ks
	}
	return nil
}

// hostWithKpasswdPort returns addr with its port replaced by the kpasswd port
// (464), adding the port when addr carries none. Bracketed IPv6 literals are
// handled by net.SplitHostPort/JoinHostPort.
func hostWithKpasswdPort(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return net.JoinHostPort(h, "464")
	}
	return net.JoinHostPort(addr, "464")
}

// GetKpasswdServers returns the count of kpasswd servers available and a map of kpasswd host names keyed on preference order.
// https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html#realms - see kpasswd_server section
//
// Like GetKDCs, krb5.conf is consulted first (including a NetBIOS/DNS alias
// fallback) and DNS SRV records are only used when the configuration yields no
// server. This keeps a kpasswd request on the configured DC rather than
// requiring _kpasswd._tcp SRV records to resolve.
func (c *Config) GetKpasswdServers(realm string, tcp bool) (int, map[int]string, error) {
	kdcs := make(map[int]string)
	var count int

	// Resolve from krb5.conf first.
	ks := c.kpasswdServersForRealm(realm)

	// Alias fallback: the caller may name the realm by a form (NetBIOS short
	// name, lower-cased DNS form, …) that differs from the c.Realms entry.
	// Mirrors the equivalent fallback in GetKDCs.
	if len(ks) == 0 && c.RealmAliases != nil {
		for _, eq := range c.RealmAliases.Equivalents(realm) {
			if strings.EqualFold(eq, realm) {
				continue
			}
			if ks = c.kpasswdServersForRealm(eq); len(ks) > 0 {
				break
			}
		}
	}

	if len(ks) > 0 {
		count = len(ks)
		kdcs = randServOrder(ks)
		return count, kdcs, nil
	}

	if !c.LibDefaults.DNSLookupKDC {
		return count, kdcs, fmt.Errorf("no kpasswd or kadmin defined in configuration for realm %s", realm)
	}

	// DNS SRV fallback.
	proto := "udp"
	if tcp {
		proto = "tcp"
	}
	n, addrs, err := dnsutils.OrderedSRV("kpasswd", proto, realm)
	if err != nil {
		return count, kdcs, err
	}
	if n < 1 {
		n, addrs, err = dnsutils.OrderedSRV("kerberos-adm", proto, realm)
		if err != nil {
			return count, kdcs, err
		}
	}
	if len(addrs) < 1 {
		return count, kdcs, fmt.Errorf("no kpasswd or kadmin SRV records found for realm %s", realm)
	}
	count = n
	for k, v := range addrs {
		kdcs[k] = strings.TrimRight(v.Target, ".") + ":" + strconv.Itoa(int(v.Port))
	}
	return count, kdcs, nil
}

func randServOrder(ks []string) map[int]string {
	kdcs := make(map[int]string)
	count := len(ks)
	i := 1
	if count > 1 {
		l := len(ks)
		for l > 0 {
			ri := rand.Intn(l)
			kdcs[i] = ks[ri]
			if l > 1 {
				// Remove the entry from the source slice by swapping with the last entry and truncating
				ks[len(ks)-1], ks[ri] = ks[ri], ks[len(ks)-1]
				ks = ks[:len(ks)-1]
				l = len(ks)
			} else {
				l = 0
			}
			i++
		}
	} else {
		kdcs[i] = ks[0]
	}
	return kdcs
}
