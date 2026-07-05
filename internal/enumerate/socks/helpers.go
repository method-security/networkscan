package socks

import (
	// Standard
	"context"
	"net"
	"time"

	// Generated
	socksfern "github.com/Method-Security/networkscan/generated/go/enumerate/socks"
	"github.com/Method-Security/networkscan/internal/netdial"
)

// stepBudget caps how long an individual SOCKS protocol step (greeting,
// auth sub-negotiation, CONNECT, BIND, or UDP ASSOCIATE) is allowed to
// take. The previous shared-session deadline burned the whole budget on
// the first slow step; per-step deadlines give each phase its own headroom.
const stepBudget = 5 * time.Second

// setStepDeadline applies a per-step read/write deadline to conn. The
// deadline is the earlier of (now + stepBudget) and the caller's context
// deadline if set — so a tight --timeout still caps total work, but a
// slow earlier step does not eat into a later step's budget.
func setStepDeadline(ctx context.Context, conn net.Conn) {
	deadline := time.Now().Add(stepBudget)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
}

// dialWithTimeout opens a TCP connection to target, respecting the context deadline
// but also using an explicit dial timeout as a floor.
func dialWithTimeout(ctx context.Context, target string, seconds int) (net.Conn, error) {
	return netdial.DialContext(ctx, "tcp", target, netdial.WithTimeout(time.Duration(seconds)*time.Second))
}

// detectImplementationHint applies heuristics to guess the SOCKS server implementation.
// Each rule requires *multiple* corroborating signals; ambiguous fingerprints fall
// through to nil rather than risk a misleading guess. Returns *SocksImplementationHint
// so callers can leave the field unset (per ontology convention: no UNKNOWN sentinel).
func detectImplementationHint(
	port int,
	chosenMethod byte,
	connectRepCode *byte, // nil if CONNECT was never attempted
	bindRepCode *byte,
	responseTimeMs int64,
	socks4Supported bool,
	socks4aSupported bool,
	udpAssociateSupported bool,
) *socksfern.SocksImplementationHint {
	hint := func(h socksfern.SocksImplementationHint) *socksfern.SocksImplementationHint { return &h }

	// Port-based hints
	if torPorts[port] {
		return hint(socksfern.SocksImplementationHintTor)
	}

	// microsocks: SOCKS5-only (no v4/4a), NO_AUTH selected, no BIND support
	// (microsocks replies 0x07 = command not supported for BIND).
	// We require an explicit 0x07 reply; nil means BIND was not probed or the
	// connection failed — ambiguous and not sufficient evidence for this hint.
	socks5OnlyMinimal := !socks4Supported && !socks4aSupported &&
		chosenMethod == 0x00 &&
		!udpAssociateSupported &&
		bindRepCode != nil && *bindRepCode == 0x07
	if socks5OnlyMinimal && responseTimeMs < 50 {
		return hint(socksfern.SocksImplementationHintMicrosocks)
	}

	// OpenSSH dynamic forwarding (-D) has the same minimal signature as
	// microsocks but is in-process and generally slower than a dedicated
	// proxy on the same network.
	if socks5OnlyMinimal && responseTimeMs >= 50 && responseTimeMs < 100 {
		return hint(socksfern.SocksImplementationHintOpensshDynamic)
	}

	// Dante speaks SOCKS4 (or at least 4a) AND SOCKS5; CONNECT works, BIND may
	// be configured-off (0x07) or work (0x00) depending on access policy.
	// Only check connectRepCode when CONNECT actually ran (non-nil).
	if (socks4Supported || socks4aSupported) && connectRepCode != nil && *connectRepCode == 0x00 {
		return hint(socksfern.SocksImplementationHintDante)
	}

	// Ambiguous — leave the field unset rather than emit a UNKNOWN sentinel.
	return nil
}

// authMethodFromChoice converts the SOCKS5 method-selection byte the server
// chose into the corresponding SocksAuthMethod enum value. Returns nil for
// unknown bytes (caller leaves the field unset rather than emitting UNKNOWN).
// RFC 1928 method negotiation only reveals the single chosen method, so this
// is by design a 1:1 mapping, not a "list of allowed methods".
func authMethodFromChoice(chosenMethod byte) *socksfern.SocksAuthMethod {
	var m socksfern.SocksAuthMethod
	switch chosenMethod {
	case 0x00:
		m = socksfern.SocksAuthMethodNoAuth
	case 0x01:
		m = socksfern.SocksAuthMethodGssapi
	case 0x02:
		m = socksfern.SocksAuthMethodUsernamePassword
	default:
		return nil
	}
	return &m
}
