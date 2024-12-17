package pkcs7

import (
    "fmt"
    "errors"
    "crypto"
    "encoding/asn1"
    "crypto/rsa"
    "crypto/rand"
    "crypto/x509/pkix"

    "github.com/deatil/go-cryptobin/x509"
    "github.com/deatil/go-cryptobin/gm/sm2"
)

var ErrUnsupportedAlgorithm = errors.New("go-cryptobin/pkcs7: cannot decrypt data")

// It is recommended to use a sequential combination of the signed-data and the enveloped-data content types instead of using the signed-and-enveloped-data content type,
// since the signed-and-enveloped-data content type does not have authenticated or unauthenticated attributes,
// and does not provide enveloping of signer information other than the signature.
type signedEnvelopedData struct {
    Version                    int                        `asn1:"default:1"`
    RecipientInfos             []recipientInfo            `asn1:"set"`
    DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
    EncryptedContentInfo       encryptedContentInfo
    Certificates               rawCertificates            `asn1:"optional,tag:0"`
    CRLs                       []pkix.CertificateList     `asn1:"optional,tag:1"`
    SignerInfos                []signerInfo               `asn1:"set"`
}

func (data signedEnvelopedData) GetRecipient(cert *x509.Certificate) *recipientInfo {
    for _, recp := range data.RecipientInfos {
        if isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
            return &recp
        }
    }

    return nil
}

func (data signedEnvelopedData) GetEncryptedContentInfo() *encryptedContentInfo {
    return &data.EncryptedContentInfo
}

func parseSignedEnvelopedData(data []byte) (*PKCS7, error) {
    var sed signedEnvelopedData
    if _, err := asn1.Unmarshal(data, &sed); err != nil {
        return nil, err
    }

    certs, err := sed.Certificates.Parse()
    if err != nil {
        return nil, err
    }

    return &PKCS7{
        raw:          sed,
        Certificates: certs,
        CRLs:         sed.CRLs,
        Signers:      sed.SignerInfos,
    }, nil
}

type VerifyFunc func() error

// DecryptOnlyOne decrypts encrypted content info for the only recipient private key.
func (p7 *PKCS7) DecryptOnlyOne(pkey crypto.PrivateKey) (err error) {
    sed, ok := p7.raw.(signedEnvelopedData)
    if !ok {
        return errors.New("go-cryptobin/pkcs7: it's not SignedAndEvelopedData")
    }

    if len(sed.RecipientInfos) != 1 {
        return errors.New("go-cryptobin/pkcs7: more than one recipients or no receipient")
    }

    defer func() {
        if e := recover(); e != nil {
            p7.Content = nil

            err = errors.New(fmt.Sprintf("%v", e))
        }
    }()

    plaintext, err := decryptSed(p7, &sed, &sed.RecipientInfos[0], pkey)
    if err != nil {
        return err
    }

    p7.Content = plaintext
    return nil
}

// Decrypt decrypts encrypted content info for recipient cert and private key.
func (p7 *PKCS7) Decrypt(cert *x509.Certificate, pkey crypto.PrivateKey) (err error) {
    sed, ok := p7.raw.(signedEnvelopedData)
    if !ok {
        return errors.New("go-cryptobin/pkcs7: it's NOT SignedAndEvelopedData")
    }

    recipient := sed.GetRecipient(cert)
    if recipient == nil {
        return errors.New("go-cryptobin/pkcs7: no enveloped recipient for provided certificate")
    }

    defer func() {
        if e := recover(); e != nil {
            p7.Content = nil

            err = errors.New(fmt.Sprintf("%v", e))
        }
    }()

    plaintext, err := decryptSed(p7, &sed, recipient, pkey)
    if err != nil {
        return err
    }

    p7.Content = plaintext
    return nil
}

func decryptSed(p7 *PKCS7, sed *signedEnvelopedData, recipient *recipientInfo, pkey crypto.PrivateKey) ([]byte, error) {
    switch pkey := pkey.(type) {
        case *sm2.PrivateKey:
            contentKey, err := pkey.DecryptASN1(recipient.EncryptedKey, nil)
            if err != nil {
                return nil, err
            }

            eci := sed.GetEncryptedContentInfo()

            return encryptedContentInfoDecrypt(*eci, contentKey)
        case crypto.Decrypter:
            // Generic case to handle anything that provides the crypto.Decrypter interface.
            contentKey, err := pkey.Decrypt(rand.Reader, recipient.EncryptedKey, nil)
            if err != nil {
                return nil, err
            }

            eci := sed.GetEncryptedContentInfo()

            return encryptedContentInfoDecrypt(*eci, contentKey)
        default:
            return nil, ErrUnsupportedAlgorithm
    }
}

type SignedAndEnvelopedData struct {
    sed       signedEnvelopedData
    certs     []*x509.Certificate
    data, cek []byte
    digestOid asn1.ObjectIdentifier
    mode      Mode
}

func NewSignedAndEnvelopedData(data []byte, cipher Cipher) (*SignedAndEnvelopedData, error) {
    var key []byte
    var err error

    // Create key
    key = make([]byte, cipher.KeySize())
    _, err = rand.Read(key)
    if err != nil {
        return nil, err
    }

    encrypted, paramBytes, err := cipher.Encrypt(rand.Reader, key, data)
    if err != nil {
        return nil, err
    }

    sed := signedEnvelopedData{
        Version: 1,
        EncryptedContentInfo: encryptedContentInfo{
            ContentType: oidData,
            ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
                Algorithm: cipher.OID(),
                Parameters: asn1.RawValue{
                    FullBytes: paramBytes,
                },
            },
            EncryptedContent: marshalEncryptedContent(encrypted),
        },
    }

    return &SignedAndEnvelopedData{
        sed: sed,
        data: data,
        cek: key,
        digestOid: OidDigestAlgorithmSHA1,
        mode: DefaultMode,
    }, nil
}

func NewSMSignedAndEnvelopedData(data []byte, cipher Cipher) (*SignedAndEnvelopedData, error) {
    sd, err := NewSignedAndEnvelopedData(data, cipher)
    if err != nil {
        return nil, err
    }

    sd.SetMode(SM2Mode)
    sd.SetDigestAlgorithm(OidDigestAlgorithmSM3)

    return sd, nil
}

// This should be called before adding signers
func (saed *SignedAndEnvelopedData) SetMode(mode Mode) {
    saed.mode = mode

    saed.sed.EncryptedContentInfo.ContentType = mode.OidData()
}

// SetDigestAlgorithm sets the digest algorithm to be used in the signing process.
//
// This should be called before adding signers
func (saed *SignedAndEnvelopedData) SetDigestAlgorithm(oid asn1.ObjectIdentifier) {
    saed.digestOid = oid
}

// AddSigner is a wrapper around AddSignerChain() that adds a signer without any parent.
func (saed *SignedAndEnvelopedData) AddSigner(ee *x509.Certificate, pkey crypto.PrivateKey) error {
    var parents []*x509.Certificate
    return saed.AddSignerChain(ee, pkey, parents)
}

func (saed *SignedAndEnvelopedData) AddSignerChain(ee *x509.Certificate, pkey crypto.PrivateKey, parents []*x509.Certificate) error {
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

    saed.sed.DigestAlgorithmIdentifiers = append(saed.sed.DigestAlgorithmIdentifiers,
        pkix.AlgorithmIdentifier{Algorithm: saed.digestOid},
    )

    signFunc, err := getSignFromHashOid(pkey, saed.digestOid)
    if err != nil {
        return err
    }

    signatureOid := signFunc.OID()

    // create signature of signed attributes
    _, signature, err := signFunc.Sign(pkey, saed.data)
    if err != nil {
        return err
    }

    signer := signerInfo{
        Version:                   1,
        DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: saed.digestOid},
        DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: signatureOid},
        IssuerAndSerialNumber:     ias,
        EncryptedDigest:           signature,
    }

    saed.certs = append(saed.certs, ee)
    if len(parents) > 0 {
        saed.certs = append(saed.certs, parents...)
    }

    saed.sed.SignerInfos = append(saed.sed.SignerInfos, signer)
    return nil
}

// AddCertificate adds the certificate to the payload. Useful for parent certificates
func (saed *SignedAndEnvelopedData) AddCertificate(cert *x509.Certificate) {
    saed.certs = append(saed.certs, cert)
}

func (saed *SignedAndEnvelopedData) AddRecipient(recipient *x509.Certificate) error {
    encryptedKey, err := encryptKey(saed.cek, recipient)
    if err != nil {
        return err
    }

    ias, err := cert2issuerAndSerial(recipient)
    if err != nil {
        return err
    }

    var keyEncryptionAlgorithm asn1.ObjectIdentifier = oidEncryptionAlgorithmRSA
    if recipient.SignatureAlgorithm == x509.SM2WithSM3 {
        keyEncryptionAlgorithm = oidKeyEncryptionAlgorithmSM2
    }

    info := recipientInfo{
        Version:               1,
        IssuerAndSerialNumber: ias,
        KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
            Algorithm: keyEncryptionAlgorithm,
        },
        EncryptedKey: encryptedKey,
    }

    saed.sed.RecipientInfos = append(saed.sed.RecipientInfos, info)
    return nil
}

// Finish marshals the content and its signers
func (saed *SignedAndEnvelopedData) Finish() ([]byte, error) {
    saed.sed.Certificates = marshalCertificates(saed.certs)
    inner, err := asn1.Marshal(saed.sed)
    if err != nil {
        return nil, err
    }

    outer := contentInfo{
        ContentType: saed.mode.OidSignedEnvelopedData(),
        Content:     asn1.RawValue{
            Class: 2,
            Tag: 0,
            Bytes: inner,
            IsCompound: true,
        },
    }

    return asn1.Marshal(outer)
}

func encryptKey(key []byte, recipient *x509.Certificate) ([]byte, error) {
    if pub, ok := recipient.PublicKey.(*rsa.PublicKey); ok {
        return rsa.EncryptPKCS1v15(rand.Reader, pub, key)
    }

    if pub, ok := recipient.PublicKey.(*sm2.PublicKey); ok && pub.Curve == sm2.P256() {
        return sm2.EncryptASN1(rand.Reader, pub, key, nil)
    }

    return nil, errors.New("go-cryptobin/pkcs7: only supports RSA/SM2 key")
}
