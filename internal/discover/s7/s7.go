// Package s7 implements a deep Siemens S7 / ISO-on-TCP probe.
//
// The probe is read-only: COTP Connection Request → COTP CC → S7 Setup
// Communication → SZL reads of SSL_ID 0x0011 (Module Identification) and
// SSL_ID 0x001C (Component Identification). No PG_RUN/PG_STOP, no block
// writes, no DB writes.
//
// The same probe entry point (Probe) is used both by the standalone
// "discover s7" subcommand and by the service-fingerprint plugin at
// internal/discover/service/plugins/s7comm.go, so deepening lands in one place.
package s7

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

// TSAP variant identifiers (kept in sync with the Fern config enum-like string).
const (
	TSAPVariantAuto    = "auto"
	TSAPVariantS7_300  = "s7_300"
	TSAPVariantS7_400  = "s7_400"
	TSAPVariantS7_1200 = "s7_1200"
	TSAPVariantS7_1500 = "s7_1500"
)

// Options controls a single S7 probe attempt.
type Options struct {
	// Timeout in seconds for each network step (dial, write, read).
	// The overall probe budget is bounded by Timeout * (#steps).
	Timeout int
	// TSAPVariant selects which calling/called TSAP pair to use. "auto"
	// tries the S7-1500/1200 TSAP first and falls back to S7-300/400.
	TSAPVariant string
	// SkipSZL bails after the COTP CC + S7 SETUP succeed and skips the
	// SZL reads — useful for very-sensitive devices where any extra
	// roundtrip is unwelcome.
	SkipSZL bool
}

// tsapPair is the calling/called TSAP byte pair embedded in the COTP CR.
type tsapPair struct {
	name    string
	calling [2]byte
	called  [2]byte
}

var (
	// S7-1200 / S7-1500 modern CPUs — calling 02.00, called 03.00 (rack 0 slot 0).
	tsapS7_1500 = tsapPair{name: TSAPVariantS7_1500, calling: [2]byte{0x02, 0x00}, called: [2]byte{0x03, 0x00}}
	// S7-300 / S7-400 — calling 01.00, called 01.02 (rack 0 slot 2).
	tsapS7_300 = tsapPair{name: TSAPVariantS7_300, calling: [2]byte{0x01, 0x00}, called: [2]byte{0x01, 0x02}}
)

func variantToPair(v string) (tsapPair, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case TSAPVariantS7_1500, TSAPVariantS7_1200:
		return tsapS7_1500, true
	case TSAPVariantS7_300, TSAPVariantS7_400:
		return tsapS7_300, true
	default:
		return tsapPair{}, false
	}
}

// rackSlotFromTSAP returns the (rack, slot) encoded in the low byte of the
// called TSAP. Siemens encodes rack in the upper 3 bits and slot in the lower
// 5 bits of the second byte (the first byte is the connection type).
func rackSlotFromTSAP(called [2]byte) (rack, slot int) {
	b := called[1]
	rack = int(b>>5) & 0x07
	slot = int(b) & 0x1F
	return rack, slot
}

// Probe runs the full S7 probe against ip:port and returns whatever
// it managed to extract. Per-step failures land in stepErrors; a fatal
// error (e.g., COTP CR rejected on every TSAP variant) is returned via
// the error.
//
// Timeout values <= 0 are forwarded to the helpers as "no timeout" — the
// per-step deadline is then driven entirely by the supplied context.
// Callers (cobra commands, processors) are responsible for setting their
// own defaults; we do not invent one here.
func Probe(ctx context.Context, ip net.IP, port int, opts Options) (*protocol.S7CommServerInfo, []string, error) {
	variant := strings.ToLower(strings.TrimSpace(opts.TSAPVariant))
	if variant == "" {
		variant = TSAPVariantAuto
	}

	// Build the TSAP variant attempt order.
	var attempts []tsapPair
	if pair, ok := variantToPair(variant); ok {
		attempts = []tsapPair{pair}
	} else { // auto
		attempts = []tsapPair{tsapS7_1500, tsapS7_300}
	}

	var lastErr error
	for _, pair := range attempts {
		info, stepErrors, err := probeWithTSAP(ctx, ip, port, opts, pair)
		if err == nil {
			return info, stepErrors, nil
		}
		lastErr = fmt.Errorf("tsap %s: %w", pair.name, err)
		// Don't retry if context was cancelled.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			break
		}
	}
	return nil, nil, lastErr
}

// probeWithTSAP runs a single attempt against the supplied TSAP pair.
func probeWithTSAP(ctx context.Context, ip net.IP, port int, opts Options, pair tsapPair) (*protocol.S7CommServerInfo, []string, error) {
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	conn, err := helpers.Dial(ctx, "tcp", addr, opts.Timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// 1. COTP Connection Request → expect Connection Confirm (0xD0).
	if err := writeWithDeadline(conn, opts.Timeout, buildCOTPConnectionRequest(pair)); err != nil {
		return nil, nil, fmt.Errorf("cotp cr write: %w", err)
	}
	resp, err := readTPKT(conn, opts.Timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("cotp cr read: %w", err)
	}
	if err := verifyCOTPConnectionConfirm(resp); err != nil {
		return nil, nil, fmt.Errorf("cotp cr: %w", err)
	}

	rack, slot := rackSlotFromTSAP(pair.called)
	info := &protocol.S7CommServerInfo{
		Rack: intPtr(rack),
		Slot: intPtr(slot),
	}

	// 2. S7 Setup Communication → expect Ack-Data (type 0x03).
	if err := writeWithDeadline(conn, opts.Timeout, buildS7Setup()); err != nil {
		return info, nil, fmt.Errorf("s7 setup write: %w", err)
	}
	setupResp, err := readTPKT(conn, opts.Timeout)
	if err != nil {
		return info, nil, fmt.Errorf("s7 setup read: %w", err)
	}
	if err := verifyS7SetupAck(setupResp); err != nil {
		return info, nil, fmt.Errorf("s7 setup: %w", err)
	}

	stepErrors := []string{}

	if opts.SkipSZL {
		return info, stepErrors, nil
	}

	// 3. SZL read SSL_ID 0x0011 — Module Identification.
	if err := readAndMergeSZL(ctx, conn, opts.Timeout, 0x0011, info, &stepErrors); err != nil {
		stepErrors = append(stepErrors, fmt.Sprintf("szl 0x0011: %v", err))
	}

	// 4. SZL read SSL_ID 0x001C — Component Identification.
	if err := readAndMergeSZL(ctx, conn, opts.Timeout, 0x001C, info, &stepErrors); err != nil {
		stepErrors = append(stepErrors, fmt.Sprintf("szl 0x001C: %v", err))
	}

	// CPU family inference from the order code.
	if info.OrderCode != nil {
		if fam := cpuFamilyFromOrderCode(*info.OrderCode); fam != "" {
			info.CpuFamily = strPtr(fam)
		}
	}

	return info, stepErrors, nil
}

// readAndMergeSZL sends a Read-SZL request for sslID and merges the parsed
// fields into the given S7CommServerInfo. Returns an error only on protocol
// failure; missing fields are silently left nil.
func readAndMergeSZL(ctx context.Context, conn net.Conn, timeout int, sslID uint16, info *protocol.S7CommServerInfo, stepErrors *[]string) error {
	_ = ctx // reserved — deadlines on the conn carry the cancellation.

	if err := writeWithDeadline(conn, timeout, buildReadSZL(sslID, 0x0000)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	resp, err := readTPKT(conn, timeout)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	records, recordLen, err := parseSZLResponse(resp)
	if err != nil {
		return err
	}
	mergeSZLRecords(info, sslID, records, recordLen)
	return nil
}

// writeWithDeadline refreshes the write deadline and writes the payload.
func writeWithDeadline(conn net.Conn, timeout int, payload []byte) error {
	if err := helpers.SetWriteDeadline(conn, timeout); err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	return nil
}

// readTPKT reads exactly one RFC 1006 TPKT frame and returns its bytes
// (including the TPKT header).
func readTPKT(conn net.Conn, timeout int) ([]byte, error) {
	if err := helpers.SetReadDeadline(conn, timeout); err != nil {
		return nil, err
	}
	header := make([]byte, 4)
	if _, err := readFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 0x03 || header[1] != 0x00 {
		return nil, fmt.Errorf("not a TPKT frame (0x%02x 0x%02x)", header[0], header[1])
	}
	length := int(header[2])<<8 | int(header[3])
	if length < 4 || length > 65535 {
		return nil, fmt.Errorf("bogus TPKT length %d", length)
	}
	rest := make([]byte, length-4)
	if len(rest) > 0 {
		if _, err := readFull(conn, rest); err != nil {
			return nil, err
		}
	}
	return append(header, rest...), nil
}

// readFull is a wrapper around io.ReadFull that respects deadlines on the conn.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, fmt.Errorf("short read")
		}
	}
	return total, nil
}

// RunDiscoverS7 executes the probe against every target in config.Targets.
// It returns a complete report; individual target failures are recorded in
// per-target errors fields, never in the top-level report errors.
func RunDiscoverS7(ctx context.Context, config discoverfern.DiscoverS7Config) (discoverfern.DiscoverS7Report, error) {
	report := discoverfern.DiscoverS7Report{
		Config: &config,
		Result: &discoverfern.DiscoverS7Result{},
	}
	if len(config.Targets) == 0 {
		report.Errors = []string{"no targets supplied"}
		return report, nil
	}

	// Timeout is taken verbatim from the config. The cobra command supplies
	// the default (--timeout 5); a non-positive value here is honored as
	// "no timeout" — see helpers.HasTimeout.
	timeout := config.Timeout
	variant := TSAPVariantAuto
	if config.TsapVariant != nil {
		variant = *config.TsapVariant
	}
	skipSZL := false
	if config.SkipSzl != nil {
		skipSZL = *config.SkipSzl
	}

	details := make([]*discoverfern.S7Detail, 0, len(config.Targets))
	topErrors := []string{}

	for _, target := range config.Targets {
		host, port, err := parseHostPort(target)
		if err != nil {
			topErrors = append(topErrors, fmt.Sprintf("%s: %v", target, err))
			continue
		}

		ip, resolved, err := resolveTarget(ctx, host, timeout)
		if err != nil {
			topErrors = append(topErrors, fmt.Sprintf("%s: %v", target, err))
			continue
		}

		info, stepErrors, probeErr := Probe(ctx, ip, port, Options{
			Timeout:     timeout,
			TSAPVariant: variant,
			SkipSZL:     skipSZL,
		})
		if probeErr != nil {
			topErrors = append(topErrors, fmt.Sprintf("%s: %v", target, probeErr))
			continue
		}

		detail := &discoverfern.S7Detail{
			Socket:     net.JoinHostPort(ip.String(), strconv.Itoa(port)),
			Ip:         strPtr(ip.String()),
			Port:       port,
			Transport:  common.TransportTypeTcp,
			Protocol:   common.ProtocolTypeS7Comm,
			ServerInfo: info,
		}
		if !resolved.isIP {
			detail.Host = strPtr(host)
		}
		if len(stepErrors) > 0 {
			detail.Errors = stepErrors
		}
		details = append(details, detail)
	}

	if len(details) > 0 {
		report.Result.Details = details
	}
	if len(topErrors) > 0 {
		report.Errors = topErrors
	}
	return report, nil
}

type targetResolution struct {
	isIP bool
}

func resolveTarget(ctx context.Context, host string, timeout int) (net.IP, targetResolution, error) {
	if parsed := net.ParseIP(host); parsed != nil {
		return parsed, targetResolution{isIP: true}, nil
	}
	resolver := net.DefaultResolver
	dctx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		dctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()
	}
	ips, err := resolver.LookupIPAddr(dctx, host)
	if err != nil {
		return nil, targetResolution{}, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, targetResolution{}, fmt.Errorf("resolve %s: no addresses", host)
	}
	return ips[0].IP, targetResolution{isIP: false}, nil
}

// parseHostPort splits a "host:port" string. If port is absent, defaults to 102.
func parseHostPort(s string) (string, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, fmt.Errorf("empty target")
	}
	// Try SplitHostPort first; if it fails (no port), default to 102.
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		// Treat as bare host.
		if strings.Count(s, ":") > 1 {
			// Likely an unbracketed IPv6 — make the caller bracket it.
			return "", 0, fmt.Errorf("ambiguous target %q: bracket IPv6 like [::1]:102", s)
		}
		return s, 102, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port in %q", s)
	}
	return host, port, nil
}

func intPtr(v int) *int       { return &v }
func strPtr(v string) *string { return &v }
