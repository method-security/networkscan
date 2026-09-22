// Copyright 2022 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0
// Adapted from fingerprintx for networkscan; see the repository root LICENSE.

package telnet

import (
	"context"
	"encoding/hex"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
	utils "github.com/Method-Security/networkscan/internal/discover/service/helpers/wireio"
)

type TELNETPlugin struct{}

const TELNET = "telnet"

// https://www.rfc-editor.org/rfc/rfc854
const IAC byte = 255
const DONT byte = 254
const DO byte = 253
const WONT byte = 252
const WILL byte = 251
const SE byte = 240
const NOP byte = 241
const DM byte = 242
const BRK byte = 243
const IP byte = 244
const AO byte = 245
const AYT byte = 246
const EC byte = 247
const EL byte = 248
const GA byte = 249
const SB byte = 250

// https://users.cs.cf.ac.uk/Dave.Marshall/Internet/node141.html
const ECHO byte = 1
const SUPPRESSGOAHEAD byte = 3
const STATUS byte = 5
const TIMINGMARK byte = 6
const TERMTYPE byte = 24
const WINDOWSIZE byte = 31
const TERMSPEED byte = 32
const REMOTEFLOWCTRL byte = 33
const LINEMODE byte = 34
const ENVVAR byte = 36

// https://www.iana.org/assignments/telnet-options/telnet-options.xhtml
// Binary Transmission 	[RFC856]
// Reconnection 	[NIC 15391 of 1973]
// Approx Message Size Negotiation 	[NIC 15393 of 1973]
// Remote Controlled Trans and Echo 	[RFC726]
// Output Line Width 	[NIC 20196 of August 1978]
// Output Page Size 	[NIC 20197 of August 1978]
// Output Carriage-Return Disposition 	[RFC652]
// Output Horizontal Tab Stops 	[RFC653]
// Output Horizontal Tab Disposition 	[RFC654]
// Output Formfeed Disposition 	[RFC655]
// Output Vertical Tabstops 	[RFC656]
// Output Vertical Tab Disposition 	[RFC657]
// Output Linefeed Disposition 	[RFC658]
// Extended ASCII 	[RFC698]
// Logout 	[RFC727]
// Byte Macro 	[RFC735]
// Data Entry Terminal 	[RFC1043][RFC732]
// SUPDUP 	[RFC736][RFC734]
// SUPDUP Output 	[RFC749]
// Send Location 	[RFC779]
// End of Record 	[RFC885]
// TACACS User Identification 	[RFC927]
// Output Marking 	[RFC933]
// Terminal Location Number 	[RFC946]
// Telnet 3270 Regime 	[RFC1041]
// X.3 PAD 	[RFC1053]
// X Display Location 	[RFC1096]
// Authentication Option 	[RFC2941]
// Encryption Option 	[RFC2946]
// New Environment Option 	[RFC1572]
// TN3270E 	[RFC2355]
// XAUTH 	[Rob_Earhart]
// CHARSET 	[RFC2066]
// Telnet Remote Serial Port (RSP) 	[Robert_Barnes]
// Com Port Control Option 	[RFC2217]
// Telnet Suppress Local Echo 	[Wirt_Atmar]
// Telnet Start TLS 	[Michael_Boe]
// KERMIT 	[RFC2840]
// SEND-URL 	[David_Croft]
// FORWARD_X 	[Jeffrey_Altman]
// TELOPT PRAGMA LOGON 	[Steve_McGregory]
// TELOPT SSPI LOGON 	[Steve_McGregory]
// TELOPT PRAGMA HEARTBEAT 	[Steve_McGregory]
const BinTransmission byte = 0
const RECON byte = 2
const ApproxMsgSizeNeg byte = 4
const RemoteCtrlTE byte = 7
const OUTLINEWIDTH byte = 8
const OUTPAGESIZE byte = 9
const OUTCRD byte = 10
const OUTHTS byte = 11
const OUTHTD byte = 12
const OUTFFD byte = 13
const OUTVT byte = 14
const OUTVTD byte = 15
const OUTLD byte = 16
const EXTASCII byte = 17
const LOGOUT byte = 18
const BYTEMACRO byte = 19
const DataEntryTerm byte = 20
const SUPDUP byte = 21
const SupdupOut byte = 22
const SendLoc byte = 23
const EOR byte = 25
const TACAS byte = 26
const OM byte = 27
const TERMLOCN byte = 28
const T3270 byte = 29
const X3PAD byte = 30
const XDISP byte = 35
const AUTHOPT byte = 37
const ENCOPT byte = 38
const NEWENVOPT byte = 39
const TN327 byte = 40
const XAUTH byte = 41
const CHARSET byte = 42
const TRSP byte = 43
const COMPORT byte = 44
const TSLE byte = 45
const TSTLS byte = 46
const KERMIT byte = 47
const SENDURL byte = 48
const ForX byte = 49
const TELPL byte = 138
const TELSSPI byte = 139
const TELPRAGMA byte = 140

var TelnetCommandMap = map[byte]bool{
	IAC:  true,
	DONT: true,
	DO:   true,
	WONT: true,
	WILL: true,
	SE:   true,
	NOP:  true,
	DM:   true,
	BRK:  true,
	IP:   true,
	AO:   true,
	AYT:  true,
	EC:   true,
	EL:   true,
	GA:   true,
	SB:   true,
}

// https://users.cs.cf.ac.uk/Dave.Marshall/Internet/node141.html
// https://www.iana.org/assignments/telnet-options/telnet-options.xhtml
var TelnetOptionsMap = map[byte]bool{
	ECHO:             true,
	SUPPRESSGOAHEAD:  true,
	STATUS:           true,
	TIMINGMARK:       true,
	TERMTYPE:         true,
	WINDOWSIZE:       true,
	TERMSPEED:        true,
	REMOTEFLOWCTRL:   true,
	LINEMODE:         true,
	ENVVAR:           true,
	BinTransmission:  true,
	RECON:            true,
	ApproxMsgSizeNeg: true,
	RemoteCtrlTE:     true,
	OUTLINEWIDTH:     true,
	OUTPAGESIZE:      true,
	OUTCRD:           true,
	OUTHTS:           true,
	OUTHTD:           true,
	OUTFFD:           true,
	OUTVT:            true,
	OUTVTD:           true,
	OUTLD:            true,
	EXTASCII:         true,
	LOGOUT:           true,
	BYTEMACRO:        true,
	DataEntryTerm:    true,
	SUPDUP:           true,
	SupdupOut:        true,
	SendLoc:          true,
	EOR:              true,
	TACAS:            true,
	OM:               true,
	TERMLOCN:         true,
	T3270:            true,
	X3PAD:            true,
	XDISP:            true,
	AUTHOPT:          true,
	ENCOPT:           true,
	NEWENVOPT:        true,
	TN327:            true,
	XAUTH:            true,
	CHARSET:          true,
	TRSP:             true,
	COMPORT:          true,
	TSLE:             true,
	TSTLS:            true,
	KERMIT:           true,
	SENDURL:          true,
	ForX:             true,
	TELPL:            true,
	TELSSPI:          true,
	TELPRAGMA:        true,
}

func isTelnet(telnet []byte) error {
	msgLength := len(telnet)
	matchError := &utils.InvalidResponseError{Service: TELNET}

	if msgLength == 0 || msgLength == 1 {

		return matchError
	}

	if telnet[0] != IAC {

		return matchError
	}

	if _, ok := TelnetCommandMap[telnet[1]]; !ok {

		return matchError
	}

	if msgLength == 2 {

		return nil
	}

	_, ok := TelnetOptionsMap[telnet[2]]
	if ok {
		return nil
	}

	return matchError
}
func (p *TELNETPlugin) PortPriority(port uint16) bool {
	return port == 23
}
func (p *TELNETPlugin) Run(conn net.Conn, timeout time.Duration, target helpers.Endpoint) (*discover.ServiceDetails, error) {
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	if err := isTelnet(response); err != nil {
		return nil, nil
	}
	payload := ServiceTelnet{
		ServerData: hex.EncodeToString(response),
	}
	return helpers.MetadataResult(target, payload, false, "", common.TransportTypeTcp), nil
}
func (p *TELNETPlugin) Name() string {
	return TELNET
}
func (p *TELNETPlugin) Type() common.TransportType {
	return common.TransportTypeTcp
}
func (p *TELNETPlugin) Priority() int {
	return 4
}

var defaultTELNETPluginPorts = helpers.Ports((&TELNETPlugin{}).PortPriority)

func (p *TELNETPlugin) DefaultPorts() []int { return defaultTELNETPluginPorts }
func (p *TELNETPlugin) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discover.ServiceDetails, error) {
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	conn, target, err := helpers.ConnectService(ctx, ip, port, host, timeout, p.Type())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return p.Run(conn, helpers.Timeout(timeout), target)
}
