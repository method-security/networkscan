package pkinit

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// asn1NULL is the DER encoding of ASN.1 NULL (tag 0x05, length 0x00).
var asn1NULL = asn1.RawValue{Tag: asn1.TagNull}

// algIDSHA1 returns an AlgorithmIdentifier for SHA-1 with explicit NULL parameter.
func algIDSHA1() AlgorithmIdentifier {
	nullBytes, _ := asn1.Marshal(asn1NULL)
	return AlgorithmIdentifier{
		Algorithm:  OIDSHA1,
		Parameters: asn1.RawValue{FullBytes: nullBytes},
	}
}

// algIDSHA1WithRSA returns an AlgorithmIdentifier for sha1WithRSAEncryption with explicit NULL parameter.
func algIDSHA1WithRSA() AlgorithmIdentifier {
	nullBytes, _ := asn1.Marshal(asn1NULL)
	return AlgorithmIdentifier{
		Algorithm:  OIDSHA1WithRSA,
		Parameters: asn1.RawValue{FullBytes: nullBytes},
	}
}

// BuildSignedData creates a CMS SignedData structure per RFC 5652
// containing the provided content signed with the given certificate and key.
// Returns the DER-encoded ContentInfo wrapping SignedData.
func BuildSignedData(content []byte, contentType asn1.ObjectIdentifier, cert *x509.Certificate, privateKey *rsa.PrivateKey) ([]byte, error) {
	// 1. Build the SignerInfo (manually for full control over encoding)
	siBytes, err := buildSignerInfoRaw(cert, privateKey, contentType, content)
	if err != nil {
		return nil, fmt.Errorf("failed to build signer info: %w", err)
	}

	// 2. Build digest algorithms: SET OF AlgorithmIdentifier
	digestAlgBytes, err := marshalDigestAlgorithms()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal digest algorithms: %w", err)
	}

	// 3. Build EncapsulatedContentInfo
	encapBytes, err := buildEncapContentInfo(contentType, content)
	if err != nil {
		return nil, fmt.Errorf("failed to build encap content info: %w", err)
	}

	// 4. Build certificates [0] IMPLICIT
	certsBytes, err := marshalCertificates(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificates: %w", err)
	}

	// 5. Build SET OF SignerInfo
	siSetBytes, err := wrapInSet(siBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap signer info in SET: %w", err)
	}

	// 6. Build SignedData SEQUENCE manually
	versionBytes, _ := asn1.Marshal(3)

	var sdContent []byte
	sdContent = append(sdContent, versionBytes...)
	sdContent = append(sdContent, digestAlgBytes...)
	sdContent = append(sdContent, encapBytes...)
	sdContent = append(sdContent, certsBytes...)
	sdContent = append(sdContent, siSetBytes...)

	sdBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      sdContent,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed data: %w", err)
	}

	// 7. Wrap in ContentInfo SEQUENCE
	contentTypeBytes, _ := asn1.Marshal(OIDSignedData)
	contentExplicit, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      sdBytes,
	})

	var ciContent []byte
	ciContent = append(ciContent, contentTypeBytes...)
	ciContent = append(ciContent, contentExplicit...)

	result, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      ciContent,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal content info: %w", err)
	}
	return result, nil
}

// buildEncapContentInfo builds the EncapsulatedContentInfo SEQUENCE.
//
//	SEQUENCE {
//	    eContentType OBJECT IDENTIFIER,
//	    eContent [0] EXPLICIT OCTET STRING
//	}
func buildEncapContentInfo(contentType asn1.ObjectIdentifier, content []byte) ([]byte, error) {
	oidBytes, err := asn1.Marshal(contentType)
	if err != nil {
		return nil, err
	}

	// eContent: OCTET STRING wrapped in EXPLICIT [0]
	octetString, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagOctetString,
		Bytes: content,
	})
	if err != nil {
		return nil, err
	}
	eContentExplicit, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      octetString,
	})
	if err != nil {
		return nil, err
	}

	var eci []byte
	eci = append(eci, oidBytes...)
	eci = append(eci, eContentExplicit...)

	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      eci,
	})
}

// buildSignerInfoRaw builds a complete SignerInfo as raw DER bytes.
// This gives full control over the encoding, avoiding struct tag / RawValue issues.
//
//	SEQUENCE {
//	    version INTEGER (1),
//	    sid IssuerAndSerialNumber,
//	    digestAlgorithm AlgorithmIdentifier,
//	    signedAttrs [0] IMPLICIT SET OF Attribute,
//	    signatureAlgorithm AlgorithmIdentifier,
//	    signature OCTET STRING
//	}
func buildSignerInfoRaw(cert *x509.Certificate, privateKey *rsa.PrivateKey, contentType asn1.ObjectIdentifier, content []byte) ([]byte, error) {
	// Compute content digest
	digest := sha1.Sum(content)

	// Build signed attributes
	attrs, err := buildSignedAttrs(contentType, digest[:])
	if err != nil {
		return nil, err
	}

	// Marshal as SET for signing (tag 0x31)
	signedAttrSetBytes, err := marshalAsSet(attrs)
	if err != nil {
		return nil, err
	}

	// Sign the SET-encoded signed attributes
	attrDigest := sha1.Sum(signedAttrSetBytes)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, attrDigest[:])
	if err != nil {
		return nil, err
	}

	// Marshal as IMPLICIT [0] for the SignerInfo structure (replaces SET tag 0x31 with 0xA0)
	signedAttrImplicit, err := marshalSignedAttrsImplicit0(attrs)
	if err != nil {
		return nil, err
	}

	// Build each field
	versionBytes, _ := asn1.Marshal(1)

	sidBytes, err := asn1.Marshal(struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}{
		Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
		SerialNumber: cert.SerialNumber,
	})
	if err != nil {
		return nil, err
	}

	digestAlgBytes, _ := asn1.Marshal(algIDSHA1())
	sigAlgBytes, _ := asn1.Marshal(algIDSHA1WithRSA())
	sigBytes, _ := asn1.Marshal(signature) // []byte → OCTET STRING

	// Concatenate all fields into a SEQUENCE
	var siContent []byte
	siContent = append(siContent, versionBytes...)
	siContent = append(siContent, sidBytes...)
	siContent = append(siContent, digestAlgBytes...)
	siContent = append(siContent, signedAttrImplicit...)
	siContent = append(siContent, sigAlgBytes...)
	siContent = append(siContent, sigBytes...)

	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      siContent,
	})
}

// buildSignedAttrs builds the signed attributes for SignerInfo:
// - contentType
// - messageDigest
func buildSignedAttrs(contentType asn1.ObjectIdentifier, digest []byte) ([]Attribute, error) {
	// contentType attribute
	ctValue, err := asn1.Marshal(contentType)
	if err != nil {
		return nil, err
	}
	ctAttr := Attribute{
		Type:   OIDContentType,
		Values: asn1.RawValue{FullBytes: mustWrapInSet(ctValue)},
	}

	// messageDigest attribute
	mdValue, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagOctetString,
		Bytes: digest,
	})
	if err != nil {
		return nil, err
	}
	mdAttr := Attribute{
		Type:   OIDMessageDigest,
		Values: asn1.RawValue{FullBytes: mustWrapInSet(mdValue)},
	}

	return []Attribute{ctAttr, mdAttr}, nil
}

// marshalAsSet marshals a slice of Attribute as a SET (tag 0x31) for signing.
func marshalAsSet(attrs []Attribute) ([]byte, error) {
	var contents []byte
	for _, attr := range attrs {
		b, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		contents = append(contents, b...)
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      contents,
	})
}

// marshalSignedAttrsImplicit0 marshals attributes as [0] IMPLICIT SET OF Attribute
// for inclusion in SignerInfo (tag 0xA0 instead of 0x31).
func marshalSignedAttrsImplicit0(attrs []Attribute) ([]byte, error) {
	var contents []byte
	for _, attr := range attrs {
		b, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		contents = append(contents, b...)
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      contents,
	})
}

// marshalDigestAlgorithms builds the SET OF AlgorithmIdentifier for SHA-1.
func marshalDigestAlgorithms() ([]byte, error) {
	algBytes, err := asn1.Marshal(algIDSHA1())
	if err != nil {
		return nil, err
	}
	return wrapInSet(algBytes)
}

// marshalCertificates builds the [0] IMPLICIT certificates field.
func marshalCertificates(cert *x509.Certificate) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      cert.Raw,
	})
}

// wrapInSet wraps DER-encoded content(s) in a SET tag.
func wrapInSet(contents []byte) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      contents,
	})
}

// mustWrapInSet wraps content in a SET, panicking on error.
func mustWrapInSet(contents []byte) []byte {
	b, err := wrapInSet(contents)
	if err != nil {
		panic(fmt.Sprintf("wrapInSet failed: %v", err))
	}
	return b
}

// BuildSignedAuthPack creates a CMS SignedData wrapping an AuthPack for PKINIT.
// Returns the raw DER bytes of the ContentInfo.
func BuildSignedAuthPack(authPackBytes []byte, cert *x509.Certificate, privateKey *rsa.PrivateKey) ([]byte, error) {
	return BuildSignedData(authPackBytes, OIDPKINITAuthData, cert, privateKey)
}
