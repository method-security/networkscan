package pkinit

import (
	"encoding/asn1"
	"fmt"
)

// ParseContentInfo parses a DER-encoded CMS ContentInfo structure.
func ParseContentInfo(data []byte) (contentType asn1.ObjectIdentifier, content []byte, err error) {
	var ci ParsedContentInfo
	_, err = asn1.Unmarshal(data, &ci)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal ContentInfo: %w", err)
	}
	return ci.ContentType, ci.Content.Bytes, nil
}

// ParseSignedDataContent extracts the encapsulated content from a CMS SignedData structure.
// Returns the raw content bytes (e.g., DER-encoded KDCDHKeyInfo).
func ParseSignedDataContent(signedDataBytes []byte) ([]byte, error) {
	var sd ParsedSignedData
	_, err := asn1.Unmarshal(signedDataBytes, &sd)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal SignedData: %w", err)
	}

	// Parse the EncapsulatedContentInfo
	var eci ParsedEncapsulatedContentInfo
	_, err = asn1.Unmarshal(sd.EncapContentInfo.FullBytes, &eci)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal EncapsulatedContentInfo: %w", err)
	}

	// The eContent is [0] EXPLICIT OCTET STRING
	// Extract the OCTET STRING from the explicit tag
	if len(eci.EContent.Bytes) == 0 {
		return nil, fmt.Errorf("EncapsulatedContentInfo has no eContent")
	}

	// The Bytes inside the explicit [0] tag should be an OCTET STRING
	var octetString asn1.RawValue
	_, err = asn1.Unmarshal(eci.EContent.Bytes, &octetString)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal eContent OCTET STRING: %w", err)
	}

	return octetString.Bytes, nil
}

// ExtractKDCDHKeyInfo parses the KDC's DH key info from the CMS SignedData
// in the PA-PK-AS-REP DHRepInfo.DHSignedData field.
func ExtractKDCDHKeyInfo(dhSignedData []byte) (*KDCDHKeyInfo, error) {
	// The dhSignedData is a ContentInfo wrapping SignedData
	contentType, signedDataBytes, err := ParseContentInfo(dhSignedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DHSignedData ContentInfo: %w", err)
	}

	if !contentType.Equal(OIDSignedData) {
		return nil, fmt.Errorf("unexpected ContentInfo type in DHSignedData: %v", contentType)
	}

	// Extract the encapsulated content (KDCDHKeyInfo)
	content, err := ParseSignedDataContent(signedDataBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to extract KDCDHKeyInfo from SignedData: %w", err)
	}

	// Unmarshal KDCDHKeyInfo
	var keyInfo KDCDHKeyInfo
	_, err = asn1.Unmarshal(content, &keyInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal KDCDHKeyInfo: %w", err)
	}

	return &keyInfo, nil
}
