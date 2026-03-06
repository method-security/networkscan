package kerberos

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/jfjallid/gofork/encoding/asn1"
	"github.com/jfjallid/gokrb5/v8/client"
	"github.com/jfjallid/gokrb5/v8/config"
	"github.com/jfjallid/gokrb5/v8/crypto"
	"github.com/jfjallid/gokrb5/v8/iana/chksumtype"
	"github.com/jfjallid/gokrb5/v8/iana/etypeID"
	"github.com/jfjallid/gokrb5/v8/iana/flags"
	"github.com/jfjallid/gokrb5/v8/iana/keyusage"
	"github.com/jfjallid/gokrb5/v8/iana/nametype"
	"github.com/jfjallid/gokrb5/v8/iana/patype"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/types"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// S4UManager handles Service for User (S4U) operations for Kerberos delegation
type S4UManager struct {
	Client *client.Client
	Config *config.Config
}

// NewS4UManager creates a new S4U manager
func NewS4UManager(client *client.Client, config *config.Config) *S4UManager {
	return &S4UManager{
		Client: client,
		Config: config,
	}
}

// PerformS4U2Self performs S4U2Self to get a service ticket for the impersonated user
func (s4u *S4UManager) PerformS4U2Self(ctx context.Context, requestingUser, userDomain, impersonateUser string, tgt messages.Ticket, sessionKey types.EncryptionKey) (messages.Ticket, error) {
	log := svc1log.FromContext(ctx)

	// Create authenticator
	auth, err := types.NewAuthenticator(strings.ToUpper(userDomain), types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, requestingUser))
	if err != nil {
		return messages.Ticket{}, fmt.Errorf("failed to create authenticator: %v", err)
	}

	// Create AP-REQ
	apReq, err := messages.NewAPReq(tgt, sessionKey, auth)
	if err != nil {
		return messages.Ticket{}, fmt.Errorf("failed to create AP-REQ: %v", err)
	}

	apReqBytes, err := apReq.Marshal()
	if err != nil {
		return messages.Ticket{}, fmt.Errorf("failed to marshal AP-REQ: %v", err)
	}

	// Create TGS-REQ for S4U2Self
	tgsReq, err := messages.NewS4UTGSReq(
		types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, impersonateUser),
		types.NewPrincipalName(nametype.KRB_NT_UNKNOWN, requestingUser),
		tgt.Realm,
		s4u.Config,
	)
	if err != nil {
		return messages.Ticket{}, fmt.Errorf("failed to create S4U TGS-REQ: %v", err)
	}

	// Add PA-TGS-REQ
	tgsReq.PAData = types.PADataSequence{
		types.PAData{
			PADataType:  patype.PA_TGS_REQ,
			PADataValue: apReqBytes,
		},
	}

	// Create PA-FOR-USER (match kerbtool approach)
	paForUserData, err := s4u.createPAForUserData(impersonateUser, userDomain, sessionKey)
	if err != nil {
		return messages.Ticket{}, fmt.Errorf("failed to create PA-FOR-USER data: %v", err)
	}

	// Set required flags
	types.SetFlag(&tgsReq.ReqBody.KDCOptions, flags.Forwardable)
	types.SetFlag(&tgsReq.ReqBody.KDCOptions, flags.Renewable)
	types.SetFlag(&tgsReq.ReqBody.KDCOptions, flags.Canonicalize)

	// Add RC4 support (required for S4U)
	s4u.ensureRC4Support(&tgsReq.ReqBody.EType)

	// Add PA-FOR-USER to PA data
	tgsReq.PAData = append(tgsReq.PAData, types.PAData{
		PADataType:  patype.PA_FOR_USER,
		PADataValue: paForUserData,
	})

	// Perform TGS exchange
	_, tgsRep, err := s4u.Client.TGSExchange(tgsReq, strings.ToUpper(userDomain), tgt, sessionKey, 0)
	if err != nil {
		return messages.Ticket{}, fmt.Errorf("TGS exchange failed: %v", err)
	}

	log.Debug("Successfully performed S4U2Self")
	return tgsRep.Ticket, nil
}

// PerformS4U2Proxy performs S4U2Proxy to get a service ticket for the target SPN
func (s4u *S4UManager) PerformS4U2Proxy(ctx context.Context, requestingUser, userDomain, impersonateUser string, tgt, s4u2SelfTicket messages.Ticket, sessionKey types.EncryptionKey, spn string) error {
	log := svc1log.FromContext(ctx)

	// Create authenticator
	auth, err := types.NewAuthenticator(strings.ToUpper(userDomain), types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, requestingUser))
	if err != nil {
		return fmt.Errorf("failed to create authenticator: %v", err)
	}

	// Create AP-REQ
	apReq, err := messages.NewAPReq(tgt, sessionKey, auth)
	if err != nil {
		return fmt.Errorf("failed to create AP-REQ: %v", err)
	}

	apReqBytes, err := apReq.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal AP-REQ: %v", err)
	}

	// Create TGS-REQ for S4U2Proxy
	tgsReq, err := messages.NewS4UTGSReq(
		types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, impersonateUser),
		types.NewPrincipalName(nametype.KRB_NT_SRV_INST, spn),
		tgt.Realm,
		s4u.Config,
	)
	if err != nil {
		return fmt.Errorf("failed to create S4U TGS-REQ: %v", err)
	}

	// Add PA-TGS-REQ
	tgsReq.PAData = types.PADataSequence{
		types.PAData{
			PADataType:  patype.PA_TGS_REQ,
			PADataValue: apReqBytes,
		},
	}

	// Add PA-PAC-OPTIONS for resource-based constrained delegation
	paPacOptBytes, err := types.GetPAPacOptionsAsnMarshalled([]int{3}) // resource-based-constrained-delegation
	if err != nil {
		return fmt.Errorf("failed to create PA-PAC-OPTIONS: %v", err)
	}

	tgsReq.PAData = append(tgsReq.PAData, types.PAData{
		PADataType:  patype.PA_PAC_OPTIONS,
		PADataValue: paPacOptBytes,
	})

	// Set additional ticket (S4U2Self result)
	tgsReq.ReqBody.AdditionalTickets = append(tgsReq.ReqBody.AdditionalTickets, s4u2SelfTicket)

	// Set required flags
	opts := types.NewKrbFlags()
	types.SetFlags(&opts, []int{flags.Canonicalize, flags.Forwardable, flags.Renewable, flags.CnameInAddlTkt})
	tgsReq.KDCReqFields.ReqBody.KDCOptions = opts

	// Perform TGS exchange
	_, _, err = s4u.Client.TGSExchange(tgsReq, tgt.Realm, tgt, sessionKey, 0)
	if err != nil {
		return fmt.Errorf("TGS exchange failed: %v", err)
	}

	log.Debug("Successfully performed S4U2Proxy")
	return nil
}

// createPAForUserData creates PA-FOR-USER data for S4U2Self requests
func (s4u *S4UManager) createPAForUserData(impersonateUser, userDomain string, sessionKey types.EncryptionKey) ([]byte, error) {
	s4uByteArray := bytes.NewBuffer([]byte{})
	if err := binary.Write(s4uByteArray, binary.LittleEndian, nametype.KRB_NT_PRINCIPAL); err != nil {
		return nil, fmt.Errorf("failed to write name type: %v", err)
	}
	if err := binary.Write(s4uByteArray, binary.LittleEndian, []byte(impersonateUser+userDomain+"Kerberos")); err != nil {
		return nil, fmt.Errorf("failed to write PA-FOR-USER data: %v", err)
	}

	checksumEtype, err := crypto.GetChksumEtype(chksumtype.KERB_CHECKSUM_HMAC_MD5)
	if err != nil {
		return nil, fmt.Errorf("failed to get checksum etype: %v", err)
	}
	cksumHash, err := checksumEtype.GetChecksumHash(sessionKey.KeyValue, s4uByteArray.Bytes(), keyusage.KERB_NON_KERB_CKSUM_SALT)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate checksum: %v", err)
	}

	impersonatedPrinc := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, impersonateUser)
	paForUser := types.PAForUser{
		UserName:  impersonatedPrinc,
		UserRealm: userDomain,
		Chksum: types.Checksum{
			CksumType: checksumEtype.GetHashID(),
			Checksum:  cksumHash,
		},
		AuthPackage: "Kerberos",
	}

	paForUserBuf, err := asn1.Marshal(paForUser)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PA-FOR-USER: %v", err)
	}

	return paForUserBuf, nil
}

// ensureRC4Support ensures RC4 encryption is included in the EType list (required for S4U)
func (s4u *S4UManager) ensureRC4Support(etypes *[]int32) {
	foundRC4 := false
	for _, etype := range *etypes {
		if etype == etypeID.RC4_HMAC {
			foundRC4 = true
			break
		}
	}
	if !foundRC4 {
		*etypes = append(*etypes, etypeID.RC4_HMAC)
	}
}
