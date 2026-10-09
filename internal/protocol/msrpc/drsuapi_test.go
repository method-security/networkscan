package msrpc

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	drsuapi "github.com/oiweiwei/go-msrpc/msrpc/drsr/drsuapi/v4"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

type credentialTestConn struct {
	dcerpc.Conn
	ctx context.Context
}

func (c credentialTestConn) Context() context.Context { return c.ctx }

type credentialTestClient struct {
	drsuapi.DrsuapiClient
	conn dcerpc.Conn
}

func (c credentialTestClient) Conn() dcerpc.Conn { return c.conn }

func TestExtractUserCredentialsPasswordAttributes(t *testing.T) {
	decode := func(value string) []byte {
		t.Helper()
		data, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	attribute := func(id uint32, value string) *drsuapi.Attribute {
		return &drsuapi.Attribute{
			AttributeType: id,
			AttributeValue: &drsuapi.AttributeValueBlock{
				Values: []*drsuapi.AttributeValue{{Value: decode(value)}},
			},
		}
	}
	current := attribute(0x9005A, "101112131415161718191a1b1c1d1e1ff1316aeb0ea57b3786268decd58132574639b7a5")
	history := attribute(0x9005E, "101112131415161718191a1b1c1d1e1fe4df0c561eff8079de592930ea63e87d6efa065a")
	lm := attribute(0x90037, "101112131415161718191a1b1c1d1e1fdd98715d1fdd8c696f0f1a173c36509c54c4ef4f")
	sid := attribute(0x90092, "010500000000000515000000010000000200000003000000f4010000")

	for _, test := range []struct {
		name         string
		attributes   []*drsuapi.Attribute
		noSessionKey bool
		ntHash       string
		lmHash       string
	}{
		{
			name:       "current NT hash without password history",
			attributes: []*drsuapi.Attribute{current},
			ntHash:     "00112233445566778899aabbccddeeff",
		},
		{
			name:       "current hashes with password history",
			attributes: []*drsuapi.Attribute{history, current, lm},
			ntHash:     "00112233445566778899aabbccddeeff",
			lmHash:     "ffeeddccbbaa99887766554433221100",
		},
		{name: "password history only", attributes: []*drsuapi.Attribute{history}},
		{name: "missing password attributes"},
		{name: "absent NT value block", attributes: []*drsuapi.Attribute{{AttributeType: 0x9005A}}},
		{
			name:       "empty NT value block",
			attributes: []*drsuapi.Attribute{{AttributeType: 0x9005A, AttributeValue: &drsuapi.AttributeValueBlock{}}},
		},
		{name: "malformed NT value", attributes: []*drsuapi.Attribute{attribute(0x9005A, "00")}},
		{
			name:         "unavailable session key",
			attributes:   []*drsuapi.Attribute{current, lm},
			noSessionKey: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := gssapi.NewSecurityContext(context.Background())
			if !test.noSessionKey {
				gssapi.SetAttribute(ctx, gssapi.AttributeSessionKey, decode("000102030405060708090a0b0c0d0e0f"))
			}
			client := &DRSUAPIClient{
				client: credentialTestClient{conn: credentialTestConn{ctx: ctx}},
				conn:   credentialTestConn{ctx: context.Background()},
			}
			response := &drsuapi.GetNCChangesResponse{
				OutVersion: 6,
				Out: &drsuapi.MessageGetNCChangesReply{
					Value: &drsuapi.MessageGetNCChangesReply_V6{
						V6: &drsuapi.MessageGetNCChangesReplyV6{
							ObjectsCount: 1,
							Objects: &drsuapi.ReplicationEntityInfoList{
								EntityInfo: &drsuapi.EntityInfo{
									AttributeBlock: &drsuapi.AttributeBlock{Attribute: append(test.attributes, sid)},
								},
							},
						},
					},
				},
			}
			entry, err := client.ExtractUserCredentials(context.Background(), "example-user", "example.test", response, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, hash := range []struct {
				name     string
				actual   *string
				expected string
			}{{"NT", entry.NtHash, test.ntHash}, {"LM", entry.LmHash, test.lmHash}} {
				if hash.expected == "" {
					if hash.actual != nil {
						t.Errorf("unexpected %s hash: %s", hash.name, *hash.actual)
					}
				} else if hash.actual == nil || *hash.actual != hash.expected {
					t.Errorf("%s hash = %v, want %s", hash.name, hash.actual, hash.expected)
				}
			}
		})
	}
}
