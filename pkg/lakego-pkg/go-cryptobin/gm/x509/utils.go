package x509

import (
    "bytes"
    "errors"
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/gm/sm2"
)

// CreateCertificate creates a new certificate based on a template. The
// following members of template are used: SerialNumber, Subject, NotBefore,
// NotAfter, KeyUsage, ExtKeyUsage, UnknownExtKeyUsage, BasicConstraintsValid,
// IsCA, MaxPathLen, SubjectKeyId, DNSNames, PermittedDNSDomainsCritical,
// PermittedDNSDomains, SignatureAlgorithm.
//
// The certificate is signed by parent. If parent is equal to template then the
// certificate is self-signed. The parameter pub is the public key of the
// signee and priv is the private key of the signer.
//
// The returned slice is the certificate in DER encoding.
//
// All keys types that are implemented via crypto.Signer are supported (This
// includes *rsa.PublicKey and *ecdsa.PublicKey.)
func CreateCertificate(template, parent *Certificate, publicKey *sm2.PublicKey, signer crypto.Signer) ([]byte, error) {
    if template.SerialNumber == nil {
        return nil, errors.New("x509: no SerialNumber given")
    }

    hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(signer.Public(), template.SignatureAlgorithm)
    if err != nil {
        return nil, err
    }

    publicKeyBytes, publicKeyAlgorithm, err := marshalPublicKey(publicKey)
    if err != nil {
        return nil, err
    }

    asn1Issuer, err := subjectBytes(parent)
    if err != nil {
        return nil, err
    }

    asn1Subject, err := subjectBytes(template)
    if err != nil {
        return nil, err
    }

    if !bytes.Equal(asn1Issuer, asn1Subject) && len(parent.SubjectKeyId) > 0 {
        template.AuthorityKeyId = parent.SubjectKeyId
    }

    extensions, err := buildExtensions(template)
    if err != nil {
        return nil, err
    }
    encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}
    c := tbsCertificate{
        Version:            2,
        SerialNumber:       template.SerialNumber,
        SignatureAlgorithm: signatureAlgorithm,
        Issuer:             asn1.RawValue{FullBytes: asn1Issuer},
        Validity:           validity{template.NotBefore.UTC(), template.NotAfter.UTC()},
        Subject:            asn1.RawValue{FullBytes: asn1Subject},
        PublicKey:          publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey},
        Extensions:         extensions,
    }

    tbsCertContents, err := asn1.Marshal(c)
    if err != nil {
        return nil, err
    }

    c.Raw = tbsCertContents

    digest := tbsCertContents
    switch template.SignatureAlgorithm {
        case SM2WithSM3, SM2WithSHA1, SM2WithSHA256:
            break
        default:
            h := hashFunc.New()
            h.Write(tbsCertContents)
            digest = h.Sum(nil)
    }

    var signerOpts crypto.SignerOpts
    signerOpts = hashFunc
    if template.SignatureAlgorithm != 0 && template.SignatureAlgorithm.isRSAPSS() {
        signerOpts = &rsa.PSSOptions{
            SaltLength: rsa.PSSSaltLengthEqualsHash,
            Hash:       crypto.Hash(hashFunc),
        }
    }

    var signature []byte
    signature, err = signer.Sign(rand.Reader, digest, signerOpts)
    if err != nil {
        return nil, err
    }

    return asn1.Marshal(certificate{
        nil,
        c,
        signatureAlgorithm,
        asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
    })
}
