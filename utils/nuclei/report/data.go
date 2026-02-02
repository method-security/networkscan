package nuclei

import (
	// Generated
	nuclei "github.com/Method-Security/networkscan/generated/go/common/nuclei"
	// External
	nout "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// getTargetURL extracts the target URL from a ResultEvent for network context.
func getTargetURL(ev *nout.ResultEvent) string {
	// Return URL directly without complex parsing
	return ev.URL
}

// getRequestResponse extracts request and response data from a ResultEvent.
func getRequestResponse(ev *nout.ResultEvent) *nuclei.NetworkRequestResponse {
	// Return nil if both request and response are empty
	if ev.Request == "" && ev.Response == "" {
		return nil
	}

	// Return structured request/response data
	return &nuclei.NetworkRequestResponse{
		Request:  stringPtr(ev.Request),
		Response: stringPtr(ev.Response),
	}
}

// stringPtr returns a pointer to a string, or nil if empty
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
