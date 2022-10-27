package sign

import (
    "fmt"
    "time"
    "bytes"
    "errors"
    "encoding/asn1"
    "crypto/subtle"
    "crypto/x509"
)

type unsignedData []byte

// Verify is a wrapper around VerifyWithChain() that initializes an empty
// trust store, effectively disabling certificate verification when validating
// a signature.
func (this *PKCS7) Verify() (err error) {
    return this.VerifyWithChain(nil)
}

// VerifyWithChain checks the signatures of a PKCS7 object.
//
// If truststore is not nil, it also verifies the chain of trust of
// the end-entity signer cert to one of the roots in the
// truststore. When the PKCS7 object includes the signing time
// authenticated attr verifies the chain at that time and UTC now
// otherwise.
func (this *PKCS7) VerifyWithChain(truststore *x509.CertPool) (err error) {
    if len(this.Signers) == 0 {
        return errors.New("pkcs7: Message has no signers")
    }

    for _, signer := range this.Signers {
        if err := verifySignature(this, signer, truststore); err != nil {
            return err
        }
    }

    return nil
}

// VerifyWithChainAtTime checks the signatures of a PKCS7 object.
//
// If truststore is not nil, it also verifies the chain of trust of
// the end-entity signer cert to a root in the truststore at
// currentTime. It does not use the signing time authenticated
// attribute.
func (this *PKCS7) VerifyWithChainAtTime(truststore *x509.CertPool, currentTime time.Time) (err error) {
    if len(this.Signers) == 0 {
        return errors.New("pkcs7: Message has no signers")
    }

    for _, signer := range this.Signers {
        if err := verifySignatureAtTime(this, signer, truststore, currentTime); err != nil {
            return err
        }
    }

    return nil
}

func verifySignatureAtTime(p7 *PKCS7, signer signerInfo, truststore *x509.CertPool, currentTime time.Time) (err error) {
    signedData := p7.Content
    ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
    if ee == nil {
        return errors.New("pkcs7: No certificate for signer")
    }

    if len(signer.AuthenticatedAttributes) > 0 {
        var (
            digest      []byte
            signingTime time.Time
        )

        err := unmarshalAttribute(signer.AuthenticatedAttributes, oidAttributeMessageDigest, &digest)
        if err != nil {
            return err
        }

        hashFunc, err := parseHashFromOid(signer.DigestAlgorithm.Algorithm)
        if err != nil {
            return err
        }

        computed := hashFunc.Sum(p7.Content)
        if subtle.ConstantTimeCompare(digest, computed) != 1 {
            return &MessageDigestMismatchError{
                ExpectedDigest: digest,
                ActualDigest:   computed,
            }
        }

        signedData, err = marshalAttributes(signer.AuthenticatedAttributes)
        if err != nil {
            return err
        }

        err = unmarshalAttribute(signer.AuthenticatedAttributes, oidAttributeSigningTime, &signingTime)
        if err == nil {
            // signing time found, performing validity check
            if signingTime.After(ee.NotAfter) || signingTime.Before(ee.NotBefore) {
                return fmt.Errorf("pkcs7: signing time %q is outside of certificate validity %q to %q",
                    signingTime.Format(time.RFC3339),
                    ee.NotBefore.Format(time.RFC3339),
                    ee.NotAfter.Format(time.RFC3339))
            }
        }
    }

    if truststore != nil {
        _, err = verifyCertChain(ee, p7.Certificates, truststore, currentTime)
        if err != nil {
            return err
        }
    }

    // 签名
    signFunc, err := parseSignFromOid(signer.DigestEncryptionAlgorithm.Algorithm, signer.DigestAlgorithm.Algorithm)
    if err != nil {
        return err
    }

    pkey := ee.PublicKey

    checkStatus, err := signFunc.Verify(pkey, signedData, signer.EncryptedDigest)
    if !checkStatus {
        return err
    }

    return nil
}

func verifySignature(p7 *PKCS7, signer signerInfo, truststore *x509.CertPool) (err error) {
    signedData := p7.Content
    ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
    if ee == nil {
        return errors.New("pkcs7: No certificate for signer")
    }

    signingTime := time.Now().UTC()
    if len(signer.AuthenticatedAttributes) > 0 {
        var digest []byte

        err := unmarshalAttribute(signer.AuthenticatedAttributes, oidAttributeMessageDigest, &digest)
        if err != nil {
            return err
        }

        hashFunc, err := parseHashFromOid(signer.DigestAlgorithm.Algorithm)
        if err != nil {
            return err
        }

        computed := hashFunc.Sum(p7.Content)

        if subtle.ConstantTimeCompare(digest, computed) != 1 {
            return &MessageDigestMismatchError{
                ExpectedDigest: digest,
                ActualDigest:   computed,
            }
        }

        signedData, err = marshalAttributes(signer.AuthenticatedAttributes)
        if err != nil {
            return err
        }

        err = unmarshalAttribute(signer.AuthenticatedAttributes, oidAttributeSigningTime, &signingTime)
        if err == nil {
            // signing time found, performing validity check
            if signingTime.After(ee.NotAfter) || signingTime.Before(ee.NotBefore) {
                return fmt.Errorf("pkcs7: signing time %q is outside of certificate validity %q to %q",
                    signingTime.Format(time.RFC3339),
                    ee.NotBefore.Format(time.RFC3339),
                    ee.NotAfter.Format(time.RFC3339))
            }
        }
    }

    if truststore != nil {
        _, err = verifyCertChain(ee, p7.Certificates, truststore, signingTime)
        if err != nil {
            return err
        }
    }

    // 签名
    signFunc, err := parseSignFromOid(signer.DigestEncryptionAlgorithm.Algorithm, signer.DigestAlgorithm.Algorithm)
    if err != nil {
        return err
    }

    pkey := ee.PublicKey

    checkStatus, err := signFunc.Verify(pkey, signedData, signer.EncryptedDigest)
    if !checkStatus {
        return err
    }

    return nil
}

// GetOnlySigner returns an x509.Certificate for the first signer of the signed
// data payload. If there are more or less than one signer, nil is returned
func (this *PKCS7) GetOnlySigner() *x509.Certificate {
    if len(this.Signers) != 1 {
        return nil
    }

    signer := this.Signers[0]
    return getCertFromCertsByIssuerAndSerial(this.Certificates, signer.IssuerAndSerialNumber)
}

// UnmarshalSignedAttribute decodes a single attribute from the signer info
func (this *PKCS7) UnmarshalSignedAttribute(attributeType asn1.ObjectIdentifier, out interface{}) error {
    sd, ok := this.raw.(signedData)
    if !ok {
        return errors.New("pkcs7: payload is not signedData content")
    }
    if len(sd.SignerInfos) < 1 {
        return errors.New("pkcs7: payload has no signers")
    }
    attributes := sd.SignerInfos[0].AuthenticatedAttributes
    return unmarshalAttribute(attributes, attributeType, out)
}

func parseSignedData(data []byte) (*PKCS7, error) {
    var sd signedData
    asn1.Unmarshal(data, &sd)

    certs, err := sd.Certificates.Parse()
    if err != nil {
        return nil, err
    }

    var compound asn1.RawValue
    var content unsignedData

    // The Content.Bytes maybe empty on PKI responses.
    if len(sd.ContentInfo.Content.Bytes) > 0 {
        if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &compound); err != nil {
            return nil, err
        }
    }

    // Compound octet string
    if compound.IsCompound {
        if compound.Tag == 4 {
            if _, err = asn1.Unmarshal(compound.Bytes, &content); err != nil {
                return nil, err
            }
        } else {
            content = compound.Bytes
        }
    } else {
        // assuming this is tag 04
        content = compound.Bytes
    }

    return &PKCS7{
        Content:      content,
        Certificates: certs,
        CRLs:         sd.CRLs,
        Signers:      sd.SignerInfos,
        raw:          sd,
    }, nil
}

// verifyCertChain takes an end-entity certs, a list of potential intermediates and a
// truststore, and built all potential chains between the EE and a trusted root.
//
// When verifying chains that may have expired, currentTime can be set to a past date
// to allow the verification to pass. If unset, currentTime is set to the current UTC time.
func verifyCertChain(ee *x509.Certificate, certs []*x509.Certificate, truststore *x509.CertPool, currentTime time.Time) (chains [][]*x509.Certificate, err error) {
    intermediates := x509.NewCertPool()
    for _, intermediate := range certs {
        intermediates.AddCert(intermediate)
    }
    verifyOptions := x509.VerifyOptions{
        Roots:         truststore,
        Intermediates: intermediates,
        KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
        CurrentTime:   currentTime,
    }
    chains, err = ee.Verify(verifyOptions)
    if err != nil {
        return chains, fmt.Errorf("pkcs7: failed to verify certificate chain: %v", err)
    }
    return
}

// MessageDigestMismatchError is returned when the signer data digest does not
// match the computed digest for the contained content
type MessageDigestMismatchError struct {
    ExpectedDigest []byte
    ActualDigest   []byte
}

func (err *MessageDigestMismatchError) Error() string {
    return fmt.Sprintf("pkcs7: Message digest mismatch\n\tExpected: %X\n\tActual  : %X", err.ExpectedDigest, err.ActualDigest)
}

func getCertFromCertsByIssuerAndSerial(certs []*x509.Certificate, ias issuerAndSerial) *x509.Certificate {
    for _, cert := range certs {
        if isCertMatchForIssuerAndSerial(cert, ias) {
            return cert
        }
    }
    return nil
}

func unmarshalAttribute(attrs []attribute, attributeType asn1.ObjectIdentifier, out interface{}) error {
    for _, attr := range attrs {
        if attr.Type.Equal(attributeType) {
            _, err := asn1.Unmarshal(attr.Value.Bytes, out)
            return err
        }
    }
    return errors.New("pkcs7: attribute type not in attributes")
}

func isCertMatchForIssuerAndSerial(cert *x509.Certificate, ias issuerAndSerial) bool {
    return cert.SerialNumber.Cmp(ias.SerialNumber) == 0 && bytes.Equal(cert.RawIssuer, ias.IssuerName.FullBytes)
}
