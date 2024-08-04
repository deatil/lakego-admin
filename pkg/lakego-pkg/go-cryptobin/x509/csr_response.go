package x509

import (
    "bytes"
    "errors"
    "crypto/rand"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/gm/sm2"
)

// see GM docs at GM/T 0092-2020

// CSRResponse represents the response of a certificate signing request.
type CSRResponse struct {
    SignCerts         []*Certificate
    EncryptPrivateKey *sm2.PrivateKey
    EncryptCerts      []*Certificate
}

// GM/T 0092-2020 Specification of certificate request syntax based on SM2 cryptographic algorithm.
// Section 8 and Appendix A
//
// CSRResponse ::= SEQUENCE {
//     signCertificate CertificateSet,
//     encryptedPrivateKey [0] SM2EnvelopedKey OPTIONAL,
//     encryptCertificate  [1] CertificateSet OPTIONAL
// }
type tbsCSRResponse struct {
    // SignCerts ::= SET OF Certificate
    SignCerts           []asn1.RawValue `asn1:"set"`
    EncryptedPrivateKey asn1.RawValue   `asn1:"optional,tag:0"`
    EncryptCerts        rawCertificates `asn1:"optional,tag:1"`
}

type rawCertificates struct {
    Raw asn1.RawContent
}

// ParseCSRResponse parses a CSRResponse from DER format.
// We do NOT verify the cert chain here, it's the caller's responsibility.
func ParseCSRResponse(signPrivateKey *sm2.PrivateKey, der []byte) (CSRResponse, error) {
    result := CSRResponse{}

    var resp tbsCSRResponse
    rest, err := asn1.Unmarshal(der, &resp)
    if err != nil || len(rest) > 0 {
        return result, errors.New("x509: invalid CSRResponse asn1 data")
    }

    signCerts := make([]*Certificate, len(resp.SignCerts))
    for i, rawCert := range resp.SignCerts {
        signCert, err := ParseCertificate(rawCert.FullBytes)
        if err != nil {
            return result, err
        }

        signCerts[i] = signCert
    }

    // check sign public key against the private key
    if !signPrivateKey.PublicKey.Equal(signCerts[0].PublicKey) {
        return result, errors.New("x509: sign cert public key mismatch")
    }

    var encPrivateKey *sm2.PrivateKey
    if len(resp.EncryptedPrivateKey.Bytes) > 0 {
        encPrivateKey, err = ParseSM2EnvelopedPrivateKey(signPrivateKey, resp.EncryptedPrivateKey.Bytes)
        if err != nil {
            return result, err
        }
    }

    var encryptCerts []*Certificate
    if len(resp.EncryptCerts.Raw) > 0 {
        encryptCerts, err = resp.EncryptCerts.Parse()
        if err != nil {
            return result, err
        }
    }

    // check the public key of the encrypt certificate
    if encPrivateKey != nil && len(encryptCerts) == 0 {
        return result, errors.New("x509: missing encrypt certificate")
    }

    if encPrivateKey != nil && !encPrivateKey.PublicKey.Equal(encryptCerts[0].PublicKey) {
        return result, errors.New("x509: encrypt key pair mismatch")
    }

    result.SignCerts = signCerts
    result.EncryptPrivateKey = encPrivateKey
    result.EncryptCerts = encryptCerts
    return result, nil
}

// MarshalCSRResponse marshals a CSRResponse to DER format.
func MarshalCSRResponse(
    signCerts         []*Certificate,
    encryptPrivateKey *sm2.PrivateKey,
    encryptCerts      []*Certificate,
    opts              ...EnvelopedOpts,
) ([]byte, error) {
    if len(signCerts) == 0 {
        return nil, errors.New("x509: no sign certificate")
    }

    signPubKey, ok := signCerts[0].PublicKey.(*sm2.PublicKey)
    if !ok {
        return nil, errors.New("x509: invalid sign public key")
    }

    // check the public key of the encrypt certificate
    if encryptPrivateKey != nil && len(encryptCerts) == 0 {
        return nil, errors.New("x509: missing encrypt certificate")
    }

    if encryptPrivateKey != nil && !encryptPrivateKey.PublicKey.Equal(encryptCerts[0].PublicKey) {
        return nil, errors.New("x509: encrypt key pair mismatch")
    }

    resp := tbsCSRResponse{}
    resp.SignCerts = make([]asn1.RawValue, 0, len(signCerts))
    for _, cert := range signCerts {
        resp.SignCerts = append(resp.SignCerts, asn1.RawValue{FullBytes: cert.Raw})
    }

    if encryptPrivateKey != nil && len(encryptCerts) > 0 {
        privateKeyBytes, err := MarshalSM2EnvelopedPrivateKey(rand.Reader, signPubKey, encryptPrivateKey, opts...)
        if err != nil {
            return nil, err
        }

        resp.EncryptedPrivateKey = asn1.RawValue{
            Class: asn1.ClassContextSpecific,
            Tag: 0,
            IsCompound: true,
            Bytes: privateKeyBytes,
        }
        resp.EncryptCerts = marshalCertificates(encryptCerts)
    }

    return asn1.Marshal(resp)
}

// concats and wraps the certificates in the RawValue structure
func marshalCertificates(certs []*Certificate) rawCertificates {
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
    var value = asn1.RawValue{
        Bytes: certs,
        Class: asn1.ClassContextSpecific,
        Tag: 0,
        IsCompound: true,
    }

    b, err := asn1.Marshal(value)
    if err != nil {
        return rawCertificates{}, err
    }

    return rawCertificates{Raw: b}, nil
}

func (raw rawCertificates) Parse() ([]*Certificate, error) {
    if len(raw.Raw) == 0 {
        return nil, nil
    }

    var value asn1.RawValue
    if _, err := asn1.Unmarshal(raw.Raw, &value); err != nil {
        return nil, err
    }

    return ParseCertificates(value.Bytes)
}
