package sign

import (
    "fmt"
    "time"
    "bytes"
    "math/big"
    "crypto"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"
)

// SignedData is an opaque data structure for creating signed data payloads
type SignedData struct {
    sd                  signedData
    certs               []*x509.Certificate
    data, messageDigest []byte
    digestOid           asn1.ObjectIdentifier
    encryptionOid       asn1.ObjectIdentifier
}

// NewSignedData takes data and initializes a PKCS7 SignedData struct that is
// ready to be signed via AddSigner. The digest algorithm is set to SHA1 by default
// and can be changed by calling SetDigestAlgorithm.
func NewSignedData(data []byte) (*SignedData, error) {
    content, err := asn1.Marshal(data)
    if err != nil {
        return nil, err
    }
    ci := contentInfo{
        ContentType: oidData,
        Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
    }
    sd := signedData{
        ContentInfo: ci,
        Version:     1,
    }
    return &SignedData{
        sd: sd,
        data: data,
        digestOid: oidDigestAlgorithmSHA1,
        encryptionOid: oidDigestAlgorithmRSASHA1,
    }, nil
}

// SignerInfoConfig are optional values to include when adding a signer
type SignerInfoConfig struct {
    ExtraSignedAttributes   []Attribute
    ExtraUnsignedAttributes []Attribute
}

type signedData struct {
    Version                    int                        `asn1:"default:1"`
    DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
    ContentInfo                contentInfo
    Certificates               rawCertificates        `asn1:"optional,tag:0"`
    CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
    SignerInfos                []signerInfo           `asn1:"set"`
}

type signerInfo struct {
    Version                   int `asn1:"default:1"`
    IssuerAndSerialNumber     issuerAndSerial
    DigestAlgorithm           pkix.AlgorithmIdentifier
    AuthenticatedAttributes   []attribute `asn1:"optional,omitempty,tag:0"`
    DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
    EncryptedDigest           []byte
    UnauthenticatedAttributes []attribute `asn1:"optional,omitempty,tag:1"`
}

type attribute struct {
    Type  asn1.ObjectIdentifier
    Value asn1.RawValue `asn1:"set"`
}

func marshalAttributes(attrs []attribute) ([]byte, error) {
    encodedAttributes, err := asn1.Marshal(struct {
        A []attribute `asn1:"set"`
    }{A: attrs})
    if err != nil {
        return nil, err
    }

    // Remove the leading sequence octets
    var raw asn1.RawValue
    asn1.Unmarshal(encodedAttributes, &raw)
    return raw.Bytes, nil
}

type rawCertificates struct {
    Raw asn1.RawContent
}

type issuerAndSerial struct {
    IssuerName   asn1.RawValue
    SerialNumber *big.Int
}

// SetDigestAlgorithm sets the digest algorithm to be used in the signing process.
//
// This should be called before adding signers
func (this *SignedData) SetDigestAlgorithm(d asn1.ObjectIdentifier) {
    this.digestOid = d
}

// SetEncryptionAlgorithm sets the encryption algorithm to be used in the signing process.
//
// This should be called before adding signers
func (this *SignedData) SetEncryptionAlgorithm(d asn1.ObjectIdentifier) {
    this.encryptionOid = d
}

// AddSigner is a wrapper around AddSignerChain() that adds a signer without any parent.
func (this *SignedData) AddSigner(ee *x509.Certificate, pkey crypto.PrivateKey, config SignerInfoConfig) error {
    var parents []*x509.Certificate

    return this.AddSignerChain(ee, pkey, parents, config)
}

// AddSignerChain signs attributes about the content and adds certificates
// and signers infos to the Signed Data. The certificate and private key
// of the end-entity signer are used to issue the signature, and any
// parent of that end-entity that need to be added to the list of
// certifications can be specified in the parents slice.
//
// The signature algorithm used to hash the data is the one of the end-entity
// certificate.
func (this *SignedData) AddSignerChain(ee *x509.Certificate, pkey crypto.PrivateKey, parents []*x509.Certificate, config SignerInfoConfig) error {
    // Following RFC 2315, 9.2 SignerInfo type, the distinguished name of
    // the issuer of the end-entity signer is stored in the issuerAndSerialNumber
    // section of the SignedData.SignerInfo, alongside the serial number of
    // the end-entity.
    var ias issuerAndSerial
    ias.SerialNumber = ee.SerialNumber
    if len(parents) == 0 {
        // no parent, the issuer is the end-entity cert itself
        ias.IssuerName = asn1.RawValue{FullBytes: ee.RawIssuer}
    } else {
        err := verifyPartialChain(ee, parents)
        if err != nil {
            return err
        }
        // the first parent is the issuer
        ias.IssuerName = asn1.RawValue{FullBytes: parents[0].RawSubject}
    }

    this.sd.DigestAlgorithmIdentifiers = append(this.sd.DigestAlgorithmIdentifiers,
        pkix.AlgorithmIdentifier{Algorithm: this.digestOid},
    )

    hashFunc, err := parseHashFromOid(this.digestOid)
    if err != nil {
        return err
    }

    this.messageDigest = hashFunc.Sum(this.data)

    attrs := &attributes{}
    attrs.Add(oidAttributeContentType, this.sd.ContentInfo.ContentType)
    attrs.Add(oidAttributeMessageDigest, this.messageDigest)
    attrs.Add(oidAttributeSigningTime, time.Now().UTC())
    for _, attr := range config.ExtraSignedAttributes {
        attrs.Add(attr.Type, attr.Value)
    }

    finalAttrs, err := attrs.ForMarshalling()
    if err != nil {
        return err
    }

    unsignedAttrs := &attributes{}
    for _, attr := range config.ExtraUnsignedAttributes {
        unsignedAttrs.Add(attr.Type, attr.Value)
    }

    finalUnsignedAttrs, err := unsignedAttrs.ForMarshalling()
    if err != nil {
        return err
    }

    finalAttrsBytes, err := marshalAttributes(finalAttrs)
    if err != nil {
        return err
    }

    signFunc, err := parseSignFromOid(this.encryptionOid, this.digestOid)

    // create signature of signed attributes
    _, signature, err := signFunc.Sign(pkey, finalAttrsBytes)
    if err != nil {
        return err
    }

    signer := signerInfo{
        AuthenticatedAttributes:   finalAttrs,
        UnauthenticatedAttributes: finalUnsignedAttrs,
        DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: this.digestOid},
        DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: this.encryptionOid},
        IssuerAndSerialNumber:     ias,
        EncryptedDigest:           signature,
        Version:                   1,
    }

    this.certs = append(this.certs, ee)
    if len(parents) > 0 {
        this.certs = append(this.certs, parents...)
    }

    this.sd.SignerInfos = append(this.sd.SignerInfos, signer)
    return nil
}

// SignWithoutAttr issues a signature on the content of the pkcs7 SignedData.
// Unlike AddSigner/AddSignerChain, it calculates the digest on the data alone
// and does not include any signed attributes like timestamp and so on.
//
// This function is needed to sign old Android APKs, something you probably
// shouldn't do unless you're maintaining backward compatibility for old
// applications.
func (this *SignedData) SignWithoutAttr(ee *x509.Certificate, pkey crypto.PrivateKey, config SignerInfoConfig) error {
    var signature []byte
    this.sd.DigestAlgorithmIdentifiers = append(this.sd.DigestAlgorithmIdentifiers, pkix.AlgorithmIdentifier{Algorithm: this.digestOid})

    // 签名
    signFunc, err := parseSignFromOid(this.encryptionOid, this.digestOid)

    // create signature of signed attributes
    hashData, signData, err := signFunc.Sign(pkey, this.data)
    if err != nil {
        return err
    }

    this.messageDigest = hashData
    signature = signData

    var ias issuerAndSerial
    ias.SerialNumber = ee.SerialNumber
    // no parent, the issue is the end-entity cert itself
    ias.IssuerName = asn1.RawValue{FullBytes: ee.RawIssuer}

    signer := signerInfo{
        DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: this.digestOid},
        DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: this.encryptionOid},
        IssuerAndSerialNumber:     ias,
        EncryptedDigest:           signature,
        Version:                   1,
    }

    // create signature of signed attributes
    this.certs = append(this.certs, ee)
    this.sd.SignerInfos = append(this.sd.SignerInfos, signer)
    return nil
}

func (this *signerInfo) SetUnauthenticatedAttributes(extraUnsignedAttrs []Attribute) error {
    unsignedAttrs := &attributes{}
    for _, attr := range extraUnsignedAttrs {
        unsignedAttrs.Add(attr.Type, attr.Value)
    }
    finalUnsignedAttrs, err := unsignedAttrs.ForMarshalling()
    if err != nil {
        return err
    }

    this.UnauthenticatedAttributes = finalUnsignedAttrs

    return nil
}

// AddCertificate adds the certificate to the payload. Useful for parent certificates
func (this *SignedData) AddCertificate(cert *x509.Certificate) {
    this.certs = append(this.certs, cert)
}

// SetContentType sets the content type of the SignedData. For example to specify the
// content type of a time-stamp token according to RFC 3161 section 2.4.2.
func (this *SignedData) SetContentType(contentType asn1.ObjectIdentifier) {
    this.sd.ContentInfo.ContentType = contentType
}

// Detach removes content from the signed data struct to make it a detached signature.
// This must be called right before Finish()
func (this *SignedData) Detach() {
    this.sd.ContentInfo = contentInfo{ContentType: oidData}
}

// GetSignedData returns the private Signed Data
func (this *SignedData) GetSignedData() *signedData {
    return &this.sd
}

// Finish marshals the content and its signers
func (this *SignedData) Finish() ([]byte, error) {
    this.sd.Certificates = marshalCertificates(this.certs)

    inner, err := asn1.Marshal(this.sd)
    if err != nil {
        return nil, err
    }

    outer := contentInfo{
        ContentType: oidSignedData,
        Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
    }

    return asn1.Marshal(outer)
}

// RemoveAuthenticatedAttributes removes authenticated attributes from signedData
// similar to OpenSSL's PKCS7_NOATTR or -noattr flags
func (this *SignedData) RemoveAuthenticatedAttributes() {
    for i := range this.sd.SignerInfos {
        this.sd.SignerInfos[i].AuthenticatedAttributes = nil
    }
}

// RemoveUnauthenticatedAttributes removes unauthenticated attributes from signedData
func (this *SignedData) RemoveUnauthenticatedAttributes() {
    for i := range this.sd.SignerInfos {
        this.sd.SignerInfos[i].UnauthenticatedAttributes = nil
    }
}

// verifyPartialChain checks that a given cert is issued by the first parent in the list,
// then continue down the path. It doesn't require the last parent to be a root CA,
// or to be trusted in any truststore. It simply verifies that the chain provided, albeit
// partial, makes sense.
func verifyPartialChain(cert *x509.Certificate, parents []*x509.Certificate) error {
    if len(parents) == 0 {
        return fmt.Errorf("pkcs7: zero parents provided to verify the signature of certificate %q", cert.Subject.CommonName)
    }

    err := cert.CheckSignatureFrom(parents[0])
    if err != nil {
        return fmt.Errorf("pkcs7: certificate signature from parent is invalid: %v", err)
    }

    if len(parents) == 1 {
        // there is no more parent to check, return
        return nil
    }

    return verifyPartialChain(parents[0], parents[1:])
}

// concats and wraps the certificates in the RawValue structure
func marshalCertificates(certs []*x509.Certificate) rawCertificates {
    var buf bytes.Buffer
    for _, cert := range certs {
        buf.Write(cert.Raw)
    }
    rawCerts, _ := marshalCertificateBytes(buf.Bytes())
    return rawCerts
}

// Even though, the tag & length are stripped out during marshalling the
// RawContent, we have to encode it into the RawContent. If its missing,
// then `asn1.Marshal()` will strip out the certificate wrapper instead.
func marshalCertificateBytes(certs []byte) (rawCertificates, error) {
    var val = asn1.RawValue{Bytes: certs, Class: 2, Tag: 0, IsCompound: true}
    b, err := asn1.Marshal(val)
    if err != nil {
        return rawCertificates{}, err
    }
    return rawCertificates{Raw: b}, nil
}

// DegenerateCertificate creates a signed data structure containing only the
// provided certificate or certificate chain.
func DegenerateCertificate(cert []byte) ([]byte, error) {
    rawCert, err := marshalCertificateBytes(cert)
    if err != nil {
        return nil, err
    }

    emptyContent := contentInfo{ContentType: oidData}
    sd := signedData{
        Version:      1,
        ContentInfo:  emptyContent,
        Certificates: rawCert,
        CRLs:         []pkix.CertificateList{},
    }

    content, err := asn1.Marshal(sd)
    if err != nil {
        return nil, err
    }

    signedContent := contentInfo{
        ContentType: oidSignedData,
        Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
    }

    return asn1.Marshal(signedContent)
}
