package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/jfjallid/gokrb5/v8/iana/errorcode"
	"github.com/jfjallid/gokrb5/v8/messages"
	"golang.org/x/net/proxy"
)

// sendToKDC sends b to the KDC for realm and returns the raw reply bytes.
//
// Transport selection follows udp_preference_limit, but the retry logic is
// DC-aware: the KDC list is resolved once and each candidate DC is tried in
// turn. A UDP attempt answered with KRB_ERR_RESPONSE_TOO_BIG is retried over
// TCP against the SAME DC (not a freshly re-resolved, possibly different,
// round-robin address). A transport-level failure for one DC (e.g. a filtered
// TCP/88) advances to the next DC instead of dead-ending. A definitive KRBError
// (anything other than RESPONSE_TOO_BIG) is returned immediately. When every DC
// fails at the transport level the returned error names each DC and why it
// failed, so a problem like a filtered TCP port is visible instead of being
// masked behind a stale "response too big".
func (cl *Client) sendToKDC(b []byte, realm string) ([]byte, error) {
	// Resolve through the client's runtime alias table before dialing.
	// This catches per-client aliases learned at runtime (CCache load,
	// TGS referral) that Config.RealmAliases doesn't know about, and it
	// folds onto whatever canonical form c.Realms uses. GetKDCs has its
	// own Config-level alias fallback for callers outside a Client.
	if cl.aliases != nil {
		realm = cl.aliases.Resolve(realm)
	}

	// A udp_preference_limit of 1 means "always use TCP". Otherwise UDP is
	// tried first only when the request is small enough to plausibly get a
	// UDP reply; larger requests (which almost always yield larger replies)
	// go straight to TCP.
	tryUDPFirst := cl.Config.LibDefaults.UDPPreferenceLimit != 1 &&
		len(b) <= cl.Config.LibDefaults.UDPPreferenceLimit

	// Resolve the ordered KDC list once so a UDP attempt and its TCP retry
	// target the same server, and so we can iterate across DCs on failure.
	_, kdcs, err := cl.Config.GetKDCs(realm, !tryUDPFirst)
	if err != nil {
		return nil, err
	}

	var attemptErrs []string
	for i := 1; i <= len(kdcs); i++ {
		kdc := kdcs[i]
		rb, err := cl.exchangeWithKDC(kdc, b, tryUDPFirst)
		if err == nil {
			return rb, nil
		}
		// A KRBError is a definitive answer from this KDC (e.g. principal
		// unknown, clock skew); trying another DC will not change it.
		// RESPONSE_TOO_BIG is the one exception and is handled inside
		// exchangeWithKDC, so it never reaches here as a KRBError.
		if e, ok := err.(messages.KRBError); ok {
			return rb, e
		}
		attemptErrs = append(attemptErrs, fmt.Sprintf("%s (%v)", kdc, err))
	}
	return nil, fmt.Errorf("failed to reach a usable KDC for realm %s. Attempts: %s", realm, strings.Join(attemptErrs, "; "))
}

// exchangeWithKDC performs a single-DC send. When tryUDPFirst is set it sends
// over UDP and, if the KDC replies KRB_ERR_RESPONSE_TOO_BIG (or the UDP send
// itself fails), retries the SAME DC over TCP. A definitive KRBError is returned
// unchanged so the caller can stop; transport failures are returned as plain
// errors so the caller can move on to the next DC.
func (cl *Client) exchangeWithKDC(kdc string, b []byte, tryUDPFirst bool) ([]byte, error) {
	single := map[int]string{1: kdc}

	if tryUDPFirst {
		rb, errudp := dialSendUDP(single, b, cl.settings.GetDialTimeout())
		if errudp == nil {
			rb, kerr := checkForKRBError(rb)
			if kerr == nil {
				return rb, nil
			}
			if e, ok := kerr.(messages.KRBError); ok && e.ErrorCode != errorcode.KRB_ERR_RESPONSE_TOO_BIG {
				// Definitive KDC error; surface it.
				return rb, kerr
			}
			// RESPONSE_TOO_BIG: fall through to TCP against the same DC.
		}

		rb, errtcp := cl.sendTCPSingle(single, b)
		if errtcp != nil {
			if _, ok := errtcp.(messages.KRBError); ok {
				return rb, errtcp
			}
			if errudp != nil {
				return rb, fmt.Errorf("UDP failed (%v) and TCP retry failed (%v)", errudp, errtcp)
			}
			return rb, fmt.Errorf("response too big for UDP and TCP retry to %s failed: %v", kdc, errtcp)
		}
		return rb, nil
	}

	return cl.sendTCPSingle(single, b)
}

// sendTCPSingle sends b to the single KDC in kdcs over TCP and classifies a
// KRBError reply as such.
func (cl *Client) sendTCPSingle(kdcs map[int]string, b []byte) ([]byte, error) {
	rb, err := dialSendTCP(kdcs, b, cl.settings.GetDialTimeout(), cl.settings.ProxyDialer())
	if err != nil {
		return rb, err
	}
	return checkForKRBError(rb)
}

// dialSendUDP establishes a UDP connection to a KDC.
func dialSendUDP(kdcs map[int]string, b []byte, timeout time.Duration) ([]byte, error) {
	var errs []string
	for i := 1; i <= len(kdcs); i++ {
		conn, err := net.DialTimeout("udp", kdcs[i], timeout)
		if err != nil {
			errs = append(errs, fmt.Sprintf("error establishing connection to %s: %v", kdcs[i], err))
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			errs = append(errs, fmt.Sprintf("error setting deadline on connection to %s: %v", kdcs[i], err))
			continue
		}
		// conn is guaranteed to be a UDPConn
		rb, err := sendUDP(conn.(*net.UDPConn), b)
		if err != nil {
			errs = append(errs, fmt.Sprintf("error sending to %s: %v", kdcs[i], err))
			continue
		}
		return rb, nil
	}
	return nil, fmt.Errorf("error sending to a KDC: %s", strings.Join(errs, "; "))
}

// sendUDP sends bytes to connection over UDP.
func sendUDP(conn *net.UDPConn, b []byte) ([]byte, error) {
	var r []byte
	defer conn.Close()
	_, err := conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to (%s): %v", conn.RemoteAddr().String(), err)
	}
	// Size the buffer to the maximum UDP payload so a large datagram is not
	// silently truncated (which would later surface as an opaque decode error
	// rather than triggering the TCP retry path).
	udpbuf := make([]byte, 65535)
	n, _, err := conn.ReadFrom(udpbuf)
	r = udpbuf[:n]
	if err != nil {
		return r, fmt.Errorf("sending over UDP failed to %s: %v", conn.RemoteAddr().String(), err)
	}
	if len(r) < 1 {
		return r, fmt.Errorf("no response data from %s", conn.RemoteAddr().String())
	}
	return r, nil
}

// dialKDCTCP establishes a TCP connection to a KDC.
func dialSendTCP(kdcs map[int]string, b []byte, timeout time.Duration, proxyDialer proxy.Dialer) ([]byte, error) {
	var errs []string
	for i := 1; i <= len(kdcs); i++ {
		var conn net.Conn
		var err error
		if proxyDialer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			conn, err = proxyDialer.(proxy.ContextDialer).DialContext(ctx, "tcp", kdcs[i])
		} else {
			conn, err = net.DialTimeout("tcp", kdcs[i], timeout)
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("error establishing connection to %s: %v", kdcs[i], err))
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			errs = append(errs, fmt.Sprintf("error setting deadline on connection to %s: %v", kdcs[i], err))
			continue
		}
		// conn is guaranteed to be a TCPConn
		//rb, err := sendTCP(conn.(*net.TCPConn), b)
		rb, err := sendTCP(conn, b)
		if err != nil {
			errs = append(errs, fmt.Sprintf("error sending to %s: %v", kdcs[i], err))
			continue
		}
		return rb, nil
	}
	return nil, fmt.Errorf("error sending to a KDC: %s", strings.Join(errs, "; "))
}

// sendTCP sends bytes to connection over TCP.
func sendTCP(conn net.Conn, b []byte) ([]byte, error) {
	defer conn.Close()
	var r []byte
	// RFC 4120 7.2.2 specifies the first 4 bytes indicate the length of the message in big endian order.
	hb := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(hb, uint32(len(b)))
	b = append(hb, b...)

	_, err := conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to KDC (%s): %v", conn.RemoteAddr().String(), err)
	}

	sh := make([]byte, 4, 4)
	_, err = conn.Read(sh)
	if err != nil {
		return r, fmt.Errorf("error reading response size header: %v", err)
	}
	s := binary.BigEndian.Uint32(sh)

	rb := make([]byte, s, s)
	_, err = io.ReadFull(conn, rb)
	if err != nil {
		return r, fmt.Errorf("error reading response: %v", err)
	}
	if len(rb) < 1 {
		return r, fmt.Errorf("no response data from KDC %s", conn.RemoteAddr().String())
	}
	return rb, nil
}

// checkForKRBError checks if the response bytes from the KDC are a KRBError.
func checkForKRBError(b []byte) ([]byte, error) {
	var KRBErr messages.KRBError
	if err := KRBErr.Unmarshal(b); err == nil {
		return b, KRBErr
	}
	return b, nil
}
