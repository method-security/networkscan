// Package plugins provides Siemens S7comm / ISO-on-TCP service fingerprinting
// on TCP/102.
//
// This fingerprinter does a full read-only Siemens S7 probe: COTP Connection
// Request → COTP Connection Confirm → S7 Setup Communication → SZL reads of
// SSL_ID 0x0011 (Module Identification) and 0x001C (Component Identification).
// It surfaces CPU type, firmware, order code, system name, copyright,
// serial number, plant ID, location designation, and rack/slot in a typed
// S7CommServerInfo metadata payload.
//
// All steps are read-only. No PG_RUN/PG_STOP, no block writes, no DB writes.
// Per-step deadlines are driven by the timeout the parallel service-discovery
// loop hands us; if any SZL read times out we keep what we have and surface
// the partial result rather than fail the whole probe.
package plugins

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type S7CommFingerprinter struct{}

func (S7CommFingerprinter) Name() string { return "s7comm" }

func (S7CommFingerprinter) DefaultPorts() []int { return []int{102} }

// s7TSAPPair is a calling/called TSAP byte pair embedded in the COTP CR.
type s7TSAPPair struct {
	name    string
	calling [2]byte
	called  [2]byte
}

var (
	// S7-1200 / S7-1500 modern CPUs — calling 02.00, called 03.00 (rack 0 slot 0).
	s7TSAP1500 = s7TSAPPair{name: "s7_1500", calling: [2]byte{0x02, 0x00}, called: [2]byte{0x03, 0x00}}
	// S7-300 / S7-400 — calling 01.00, called 01.02 (rack 0 slot 2).
	s7TSAP300 = s7TSAPPair{name: "s7_300", calling: [2]byte{0x01, 0x00}, called: [2]byte{0x01, 0x02}}
)

// rackSlotFromTSAP returns the (rack, slot) encoded in the low byte of the
// called TSAP. Siemens encodes rack in the upper 3 bits and slot in the lower
// 5 bits of the second byte (the first byte is the connection type).
func rackSlotFromTSAP(called [2]byte) (rack, slot int) {
	b := called[1]
	rack = int(b>>5) & 0x07
	slot = int(b) & 0x1F
	return rack, slot
}

func (S7CommFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Try the modern (S7-1200/1500) TSAP first, then fall back to S7-300/400.
	// Most modern CPUs accept the 02.00/03.00 pair; older 300/400 reject it
	// with a Disconnect Request and we retry.
	attempts := []s7TSAPPair{s7TSAP1500, s7TSAP300}

	var lastErr error
	for _, pair := range attempts {
		info, err := s7Probe(ctx, ip, port, timeout, pair)
		if err == nil {
			// version is the human-facing service-version string. Prefer the
			// CPU product designation (SZL 0x001C index 7, e.g. "CPU 1515-2 PN"),
			// then the inferred family (from the MLFB), then the friendly
			// module name, and finally a bare "Siemens S7comm" if SZL failed.
			version := "Siemens S7comm"
			switch {
			case info.CpuType != nil && *info.CpuType != "":
				version = "Siemens S7comm — " + *info.CpuType
			case info.CpuFamily != nil && *info.CpuFamily != "":
				version = "Siemens S7comm — " + *info.CpuFamily
			case info.ModuleName != nil && *info.ModuleName != "":
				version = "Siemens S7comm — " + *info.ModuleName
			}
			return &discoverfern.ServiceDetails{
				Host:      host,
				Ip:        ip.String(),
				Port:      port,
				Tls:       false,
				Transport: common.TransportTypeTcp,
				Protocol:  common.ProtocolTypeS7Comm,
				Version:   &version,
				Metadata:  &discoverfern.ServiceMetadata{S7Comm: info},
			}, nil
		}
		lastErr = fmt.Errorf("tsap %s: %w", pair.name, err)
		// Don't retry if context was cancelled — the parallel-discovery loop
		// is shutting us down.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			break
		}
	}
	return nil, lastErr
}

// s7Probe runs a single COTP/S7 attempt against the supplied TSAP pair.
// The COTP CC and SETUP must both succeed for the host to be flagged S7comm;
// SZL failures degrade gracefully (we keep whatever fields we could fill in).
func s7Probe(ctx context.Context, ip net.IP, port int, timeout int, pair s7TSAPPair) (*protocol.S7CommServerInfo, error) {
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	conn, err := helpers.Dial(ctx, "tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// 1. COTP Connection Request → expect Connection Confirm (0xD0).
	if err := s7WriteWithDeadline(conn, timeout, buildS7COTPConnectionRequest(pair)); err != nil {
		return nil, fmt.Errorf("cotp cr write: %w", err)
	}
	resp, err := s7ReadTPKT(conn, timeout)
	if err != nil {
		return nil, fmt.Errorf("cotp cr read: %w", err)
	}
	if err := verifyCOTPConnectionConfirm(resp); err != nil {
		return nil, fmt.Errorf("cotp cr: %w", err)
	}

	rack, slot := rackSlotFromTSAP(pair.called)
	info := &protocol.S7CommServerInfo{
		Rack: s7IntPtr(rack),
		Slot: s7IntPtr(slot),
	}

	// 2. S7 Setup Communication → expect Ack/Ack-Data.
	if err := s7WriteWithDeadline(conn, timeout, buildS7Setup()); err != nil {
		return info, fmt.Errorf("s7 setup write: %w", err)
	}
	setupResp, err := s7ReadTPKT(conn, timeout)
	if err != nil {
		return info, fmt.Errorf("s7 setup read: %w", err)
	}
	if err := verifyS7SetupAck(setupResp); err != nil {
		return info, fmt.Errorf("s7 setup: %w", err)
	}

	// 3. SZL read SSL_ID 0x0011 — Module Identification (CPU module, MLFB, firmware).
	//    Failures are non-fatal; we keep partial data and let the next read try.
	_ = s7ReadAndMergeSZL(ctx, conn, timeout, 0x0011, info)

	// 4. SZL read SSL_ID 0x001C — Component Identification (system name, serial, plant ID, ...).
	_ = s7ReadAndMergeSZL(ctx, conn, timeout, 0x001C, info)

	// CPU family inference from the order code.
	if info.OrderCode != nil {
		if fam := cpuFamilyFromOrderCode(*info.OrderCode); fam != "" {
			info.CpuFamily = s7StrPtr(fam)
		}
	}

	return info, nil
}

// s7ReadAndMergeSZL sends a Read-SZL request for sslID and merges the parsed
// fields into the given S7CommServerInfo. Returns an error only on protocol
// failure; missing fields are silently left nil.
func s7ReadAndMergeSZL(ctx context.Context, conn net.Conn, timeout int, sslID uint16, info *protocol.S7CommServerInfo) error {
	_ = ctx // deadlines on the conn carry the cancellation
	if err := s7WriteWithDeadline(conn, timeout, buildReadSZL(sslID, 0x0000)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	resp, err := s7ReadTPKT(conn, timeout)
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

// s7WriteWithDeadline refreshes the write deadline and writes the payload.
func s7WriteWithDeadline(conn net.Conn, timeout int, payload []byte) error {
	if err := helpers.SetWriteDeadline(conn, timeout); err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	return nil
}

// s7ReadTPKT reads exactly one RFC 1006 TPKT frame and returns its bytes
// (including the TPKT header).
func s7ReadTPKT(conn net.Conn, timeout int) ([]byte, error) {
	if err := helpers.SetReadDeadline(conn, timeout); err != nil {
		return nil, err
	}
	header := make([]byte, 4)
	if _, err := s7ReadFull(conn, header); err != nil {
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
		if _, err := s7ReadFull(conn, rest); err != nil {
			return nil, err
		}
	}
	return append(header, rest...), nil
}

// s7ReadFull reads exactly len(buf) bytes from conn, returning an error
// on short read or underlying conn failure.
func s7ReadFull(conn net.Conn, buf []byte) (int, error) {
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

// cpuFamilyFromOrderCode infers the S7 family from an MLFB prefix.
// Returns "" when the prefix is unrecognised.
func cpuFamilyFromOrderCode(mlfb string) string {
	s := mlfbNormalize(mlfb)
	switch {
	case len(s) >= 6 && s[:4] == "6ES7" && s[4] >= '5' && s[4] <= '5':
		return "S7-1500"
	case len(s) >= 7 && s[:4] == "6ES7" && s[4] == '2' && s[5] == '1':
		return "S7-1200"
	case len(s) >= 6 && s[:4] == "6ES7" && s[4] == '3':
		return "S7-300"
	case len(s) >= 6 && s[:4] == "6ES7" && s[4] == '4':
		return "S7-400"
	case len(s) >= 6 && s[:4] == "6ES7" && s[4] == '1':
		return "ET200"
	case len(s) >= 4 && s[:4] == "6ED1":
		return "LOGO"
	}
	return ""
}

func mlfbNormalize(s string) string {
	out := make([]byte, 0, len(s))
	for _, c := range []byte(strings.TrimSpace(s)) {
		if c == ' ' || c == '-' {
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

func s7IntPtr(v int) *int       { return &v }
func s7StrPtr(v string) *string { return &v }
