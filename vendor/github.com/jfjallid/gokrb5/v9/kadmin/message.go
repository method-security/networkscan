package kadmin

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/jfjallid/gokrb5/v9/messages"
	"github.com/jfjallid/gokrb5/v9/types"
)

const (
	verisonHex = "ff80"
)

// Request message for changing password.
type Request struct {
	APREQ   messages.APReq
	KRBPriv messages.KRBPriv
}

// Reply message for a password change.
type Reply struct {
	MessageLength int
	Version       int
	APREPLength   int
	APREP         messages.APRep
	KRBPriv       messages.KRBPriv
	KRBError      messages.KRBError
	IsKRBError    bool
	ResultCode    uint16
	Result        string
}

// Marshal a Request into a byte slice.
func (m *Request) Marshal() (b []byte, err error) {
	b = []byte{255, 128} // protocol version number: contains the hex constant 0xff80 (big-endian integer).
	ab, e := m.APREQ.Marshal()
	if e != nil {
		err = fmt.Errorf("error marshaling AP_REQ: %v", e)
		return
	}
	if len(ab) > math.MaxUint16 {
		err = errors.New("length of AP_REQ greater then max Uint16 size")
		return
	}
	al := make([]byte, 2)
	binary.BigEndian.PutUint16(al, uint16(len(ab)))
	b = append(b, al...)
	b = append(b, ab...)
	pb, e := m.KRBPriv.Marshal()
	if e != nil {
		err = fmt.Errorf("error marshaling KRB_Priv: %v", e)
		return
	}
	b = append(b, pb...)
	if len(b)+2 > math.MaxUint16 {
		err = errors.New("length of message greater then max Uint16 size")
		return
	}
	ml := make([]byte, 2)
	binary.BigEndian.PutUint16(ml, uint16(len(b)+2))
	b = append(ml, b...)
	return
}

// krbErrorAppTag is the ASN.1 tag of a KRB-ERROR ([APPLICATION 30]). A kpasswd
// server that rejects the AP-REQ outright (e.g. KRB_AP_ERR_BADMATCH) may reply
// with a bare KRB-ERROR instead of the RFC 3244 reply framing; recognising the
// tag lets us surface that error rather than misreading it as a length/version.
const krbErrorAppTag = 0x7e

// Unmarshal a byte slice into a Reply.
func (m *Reply) Unmarshal(b []byte) error {
	// A bare KRB-ERROR (not wrapped in the kpasswd reply header) is returned by
	// some servers when the AP-REQ itself is rejected. Detect it up front so the
	// caller gets the real Kerberos error instead of a bogus version mismatch.
	if len(b) > 0 && b[0] == krbErrorAppTag {
		if err := m.KRBError.Unmarshal(b); err != nil {
			return fmt.Errorf("kadmin reply looked like a KRB-ERROR but failed to parse: %v", err)
		}
		m.IsKRBError = true
		m.ResultCode, m.Result = parseResponse(m.KRBError.EData)
		return nil
	}

	if len(b) < 6 {
		return fmt.Errorf("kadmin reply too short: %d bytes", len(b))
	}
	m.MessageLength = int(binary.BigEndian.Uint16(b[0:2]))
	m.Version = int(binary.BigEndian.Uint16(b[2:4]))
	if m.Version != 1 {
		return fmt.Errorf("kadmin reply has incorrect protocol version number: %d", m.Version)
	}
	// The length field counts the whole message including its own 2 bytes; clamp
	// it to the bytes we actually received so a too-large value can't slice OOB.
	if m.MessageLength > len(b) || m.MessageLength < 6 {
		m.MessageLength = len(b)
	}
	m.APREPLength = int(binary.BigEndian.Uint16(b[4:6]))
	if 6+m.APREPLength > m.MessageLength {
		return fmt.Errorf("kadmin reply AP-REP length %d exceeds message length %d", m.APREPLength, m.MessageLength)
	}
	if m.APREPLength != 0 {
		err := m.APREP.Unmarshal(b[6 : 6+m.APREPLength])
		if err != nil {
			return err
		}
		err = m.KRBPriv.Unmarshal(b[6+m.APREPLength : m.MessageLength])
		if err != nil {
			return err
		}
	} else {
		m.IsKRBError = true
		if err := m.KRBError.Unmarshal(b[6:m.MessageLength]); err != nil {
			return fmt.Errorf("error unmarshaling KRB-ERROR in kadmin reply: %v", err)
		}
		m.ResultCode, m.Result = parseResponse(m.KRBError.EData)
	}
	return nil
}

func parseResponse(b []byte) (c uint16, s string) {
	if len(b) < 2 {
		return
	}
	c = binary.BigEndian.Uint16(b[0:2])
	buf := bytes.NewBuffer(b[2:])
	m := make([]byte, len(b)-2)
	binary.Read(buf, binary.BigEndian, &m)
	s = string(m)
	return
}

// Decrypt the encrypted part of the KRBError within the change password Reply.
func (m *Reply) Decrypt(key types.EncryptionKey) error {
	if m.IsKRBError {
		return m.KRBError
	}
	err := m.KRBPriv.DecryptEncPart(key)
	if err != nil {
		return err
	}
	// The decrypted result data must begin with a 2-byte result code. Reject a
	// short buffer rather than letting parseResponse return a zero code, which
	// would be indistinguishable from KRB5_KPASSWD_SUCCESS.
	if len(m.KRBPriv.DecryptedEncPart.UserData) < 2 {
		return fmt.Errorf("kadmin reply result data too short: %d bytes", len(m.KRBPriv.DecryptedEncPart.UserData))
	}
	m.ResultCode, m.Result = parseResponse(m.KRBPriv.DecryptedEncPart.UserData)
	return nil
}
