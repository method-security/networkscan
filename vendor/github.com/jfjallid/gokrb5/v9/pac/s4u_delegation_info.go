package pac

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/mstypes"
	"github.com/jfjallid/ndr"
)

// S4UDelegationInfo implements https://msdn.microsoft.com/en-us/library/cc237944.aspx
type S4UDelegationInfo struct {
	S4U2proxyTarget      mstypes.RPCUnicodeString // The name of the principal to whom the application can forward the ticket.
	TransitedListSize    uint32
	S4UTransitedServices []mstypes.RPCUnicodeString `ndr:"pointer,conformant"` // List of all services that have been delegated through by this client and subsequent services or servers.. Size is value of TransitedListSize
}

// Unmarshal bytes into the S4UDelegationInfo struct
func (k *S4UDelegationInfo) Unmarshal(b []byte) (err error) {
	dec := ndr.NewDecoder(bytes.NewReader(b), true)
	err = dec.Decode(k)
	if err != nil {
		err = fmt.Errorf("error unmarshaling S4UDelegationInfo: %v", err)
	}
	return
}

func (k *S4UDelegationInfo) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), true)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(k)
	if err != nil {
		err = fmt.Errorf("error marshaling S4UDelegationInfo: %v", err)
	}
	return
}
