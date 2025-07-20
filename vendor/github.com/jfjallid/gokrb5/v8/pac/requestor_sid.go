package pac

import (
	"bytes"
	"github.com/jfjallid/mstypes"
)

// PacRequestorSid implements MS-PAC Section 2.15 PAC_REQUESTOR_SID
type PacRequestorSid struct {
	Sid mstypes.RPCSID
}

// Unmarshal bytes into the PacRequestorSid struct
func (k *PacRequestorSid) Unmarshal(b []byte) (err error) {
	r := mstypes.NewReader(bytes.NewReader(b))
	k.Sid, err = r.RPCSid()
	if err != nil {
		return
	}

	return
}

func (k *PacRequestorSid) Marshal() (buf []byte, err error) {
	w := bytes.NewBuffer(buf)
	err = k.Sid.ToWriter(w)
	if err != nil {
		return
	}
	return w.Bytes(), nil
}
