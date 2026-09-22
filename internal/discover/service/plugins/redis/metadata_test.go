package redis

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"testing"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

func TestRedisAuthMetadataKey(t *testing.T) {
	for _, required := range []bool{false, true} {
		service := helpers.MetadataResult(helpers.Endpoint{Address: netip.MustParseAddrPort("127.0.0.1:6379"), Host: "redis.test"}, ServiceRedis{AuthRequired: required}, true, "", common.TransportTypeTcptls)
		encoded, err := json.Marshal(service)
		if err != nil {
			t.Fatal(err)
		}
		var decoded discover.ServiceDetails
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		metadata := decoded.Metadata.Generic.Metadata
		if metadata["authRequired"] != strconv.FormatBool(required) {
			t.Fatalf("missing authRequired after roundtrip: %s", encoded)
		}
		if _, exists := metadata["authRequired:"]; exists {
			t.Fatalf("legacy key present: %s", encoded)
		}
	}
}
