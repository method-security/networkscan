package kerberos

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/jfjallid/gokrb5/v8/messages"
)

const maxResponseLength = 65535

// SendASReqToKDC sends an AS-REQ to the KDC over TCP and returns the raw response bytes,
// parsed AS-REP (if received), KRB-ERROR (if received), and any network/parse error.
// Wire format: 4-byte BigEndian length prefix followed by the message body (RFC 4120 §7.2.2).
func SendASReqToKDC(host string, port int, asReq messages.ASReq, timeout time.Duration) (raw []byte, asRep *messages.ASRep, krbErr *messages.KRBError, err error) {
	b, err := asReq.Marshal()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal AS-REQ: %w", err)
	}

	raw, err = sendAndReceiveKDC(host, port, b, timeout)
	if err != nil {
		return nil, nil, nil, err
	}

	return discriminateResponse(raw)
}

// SendTGSReqToKDC sends a TGS-REQ to the KDC over TCP and returns the raw response bytes,
// parsed TGS-REP (if received), KRB-ERROR (if received), and any network/parse error.
func SendTGSReqToKDC(host string, port int, tgsReq messages.TGSReq, timeout time.Duration) (raw []byte, tgsRep *messages.TGSRep, krbErr *messages.KRBError, err error) {
	b, err := tgsReq.Marshal()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal TGS-REQ: %w", err)
	}

	raw, err = sendAndReceiveKDC(host, port, b, timeout)
	if err != nil {
		return nil, nil, nil, err
	}

	if len(raw) == 0 {
		return raw, nil, nil, fmt.Errorf("empty response from KDC")
	}

	// Try KRB-ERROR first, then TGS-REP (a TGS-REQ never produces an AS-REP).
	krbErrMsg := new(messages.KRBError)
	if unmarshalErr := krbErrMsg.Unmarshal(raw); unmarshalErr == nil {
		return raw, nil, krbErrMsg, nil
	}

	rep := new(messages.TGSRep)
	if unmarshalErr := rep.Unmarshal(raw); unmarshalErr != nil {
		return raw, nil, nil, fmt.Errorf("failed to unmarshal TGS-REP: %w", unmarshalErr)
	}
	return raw, rep, nil, nil
}

// sendAndReceiveKDC handles the raw TCP send/receive with the 4-byte length prefix.
func sendAndReceiveKDC(host string, port int, msgBytes []byte, timeout time.Duration) ([]byte, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to KDC %s: %w", addr, err)
	}
	defer conn.Close() //nolint:errcheck

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	// Write 4-byte length prefix + message
	length := uint32(len(msgBytes))
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, length)
	if _, err := conn.Write(append(lenBuf, msgBytes...)); err != nil {
		return nil, fmt.Errorf("failed to send request to KDC: %w", err)
	}

	// Read 4-byte response length
	respLenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, respLenBuf); err != nil {
		return nil, fmt.Errorf("failed to read response length from KDC: %w", err)
	}
	respLen := binary.BigEndian.Uint32(respLenBuf)
	if respLen == 0 || respLen > maxResponseLength {
		return nil, fmt.Errorf("invalid response length from KDC: %d", respLen)
	}

	// Read exactly respLen bytes
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, fmt.Errorf("failed to read response from KDC: %w", err)
	}

	return respBuf, nil
}

// discriminateResponse tries to parse raw bytes as KRB-ERROR first, then AS-REP.
// ASN.1 application tag for AS-REP is 11 (encoded as 0x6B), KRB-ERROR is 30 (encoded as 0x7E).
func discriminateResponse(raw []byte) ([]byte, *messages.ASRep, *messages.KRBError, error) {
	if len(raw) == 0 {
		return raw, nil, nil, fmt.Errorf("empty response from KDC")
	}

	// Try KRB-ERROR first (tag 0x7E)
	krbErrMsg := new(messages.KRBError)
	if err := krbErrMsg.Unmarshal(raw); err == nil {
		return raw, nil, krbErrMsg, nil
	}

	// Try AS-REP (tag 0x6B)
	asRepMsg := new(messages.ASRep)
	if err := asRepMsg.Unmarshal(raw); err == nil {
		return raw, asRepMsg, nil, nil
	}

	return raw, nil, nil, fmt.Errorf("response is neither AS-REP nor KRB-ERROR (first byte: 0x%02x)", raw[0])
}
