package tr069

const (
	defaultTr069Port = 7547
	defaultTimeoutMs = 15000
	cwmpEndpoint     = "/"
	soapContentType  = `text/xml; charset="utf-8"`
	// SOAP GetRPCMethods probe — read-only discovery RPC, does not modify CPE state
	soapGetRPCMethods = `<?xml version="1.0" encoding="UTF-8"?>
<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/">
  <soap-env:Header>
    <cwmp:ID xmlns:cwmp="urn:dslforum-org:cwmp-1-0" soap-env:mustUnderstand="1">1</cwmp:ID>
  </soap-env:Header>
  <soap-env:Body>
    <cwmp:GetRPCMethods xmlns:cwmp="urn:dslforum-org:cwmp-1-0"/>
  </soap-env:Body>
</soap-env:Envelope>`
)

// cwmpVersionNamespaces is an ordered list of CWMP XML namespace URIs (newest first)
// to their version strings. Ordered to ensure deterministic detection when multiple
// namespaces appear in the same response body.
var cwmpVersionNamespaces = []struct {
	namespace string
	version   string
}{
	{"urn:dslforum-org:cwmp-1-4", "1.4"},
	{"urn:dslforum-org:cwmp-1-3", "1.3"},
	{"urn:dslforum-org:cwmp-1-2", "1.2"},
	{"urn:dslforum-org:cwmp-1-1", "1.1"},
	{"urn:dslforum-org:cwmp-1-0", "1.0"},
}

// cwmpResponseIndicators lists XML element names (or distinctive substrings) that
// appear exclusively in genuine CWMP server responses and never in the
// GetRPCMethods probe we send.  detectCWMPVersion requires at least one of these
// to be present before accepting a namespace match, preventing echo servers from
// being falsely identified as CWMP 1.0 endpoints.
// cwmpResponseIndicators lists XML element names that are exclusive to genuine
// CWMP server responses.  Each entry must be CWMP-namespaced or a method name
// specific to TR-069 so that generic SOAP servers — which may echo our
// namespace URI in a standard fault body — are not falsely flagged.
//
// Removed indicators that were too broad:
//   - ":Fault>"   — matches any SOAP fault prefix (soap:Fault, s:Fault, etc.)
//   - "Response>" — matches any XML element ending in "Response"
//
// A non-CWMP SOAP server receiving our GetRPCMethods probe can respond with a
// generic SOAP fault that (a) mentions the CWMP namespace URI from our probe in
// the fault detail and (b) contains "<s:Fault>" — satisfying both checks and
// triggering a false-positive CWMP version detection.  Restricting to
// CWMP-prefixed or probe-method-specific strings eliminates that risk.
var cwmpResponseIndicators = []string{
	// Normal response to our GetRPCMethods probe — method-specific, not in probe body
	"GetRPCMethodsResponse",
	// The MethodList payload carried in a GetRPCMethodsResponse
	"MethodList",
	// CWMP-namespaced fault — only a real CWMP endpoint uses the cwmp: prefix in faults
	"cwmp:Fault",
	// Unsolicited Inform from the CPE — CWMP-namespaced, probe body never contains these
	"cwmp:Inform",
	":InformResponse",
}

// romPagerVulnVersion is the last vulnerable RomPager version for Misfortune Cookie.
// Versions below 4.34 are vulnerable (CVE-2014-9222).
const romPagerVulnVersion = "4.34"

// miraiDTPatterns are HTTP Server header substrings associated with Mirai DT-class CPE.
var miraiDTPatterns = []string{
	"Speedport",
	"Eir D1000",
	"ZNID-GPON",
}
