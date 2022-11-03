package encrypt

import (
    "errors"
    "math/big"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"
)

var (
    // Signed Data OIDs
    oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
    oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
    oidEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
)

type issuerAndSerial struct {
    IssuerName   asn1.RawValue
    SerialNumber *big.Int
}

type envelopedData struct {
    Version              int
    RecipientInfos       []recipientInfo `asn1:"set"`
    EncryptedContentInfo encryptedContentInfo
}

type encryptedData struct {
    Version              int
    EncryptedContentInfo encryptedContentInfo
}

type recipientInfo struct {
    Version                int
    IssuerAndSerialNumber  issuerAndSerial
    KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
    EncryptedKey           []byte
}

type encryptedContentInfo struct {
    ContentType                asn1.ObjectIdentifier
    ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
    EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

type contentInfo struct {
    ContentType asn1.ObjectIdentifier
    Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

var ErrUnsupportedEncryptionAlgorithm = errors.New("pkcs7: cannot encrypt content: only DES-CBC, AES-CBC, and AES-GCM supported")

var ErrPSKNotProvided = errors.New("pkcs7: cannot encrypt content: PSK not provided")

// 配置
type Opts struct {
    Cipher     Cipher
    KeyEncrypt KeyEncrypt
}

// 默认配置
var DefaultOpts = Opts{
    Cipher:     AES256CBC,
    KeyEncrypt: KeyEncryptRSA,
}

// 加密
func Encrypt(content []byte, recipients []*x509.Certificate, opts ...Opts) ([]byte, error) {
    var eci *encryptedContentInfo
    var key []byte
    var err error

    opt := &DefaultOpts
    if len(opts) > 0 {
        opt = &opts[0]
    }

    cipher := opt.Cipher
    if cipher == nil {
        return nil, errors.New("Pkcs7: failed to encrypt PEM: unknown opts cipher")
    }

    keyEncrypt := opt.KeyEncrypt
    if keyEncrypt == nil {
        return nil, errors.New("failed to encrypt PEM: unknown opts keyEncrypt")
    }

    // 生成密钥
    key = make([]byte, cipher.KeySize())

    _, err = rand.Read(key)
    if err != nil {
        return nil, err
    }

    encrypted, paramBytes, err := cipher.Encrypt(key, content)
    if err != nil {
        return nil, err
    }

    eci = &encryptedContentInfo{
        ContentType: oidData,
        ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
            Algorithm: cipher.OID(),
            Parameters: asn1.RawValue{
                FullBytes: paramBytes,
            },
        },
        EncryptedContent: marshalEncryptedContent(encrypted),
    }

    // Prepare each recipient's encrypted cipher key
    recipientInfos := make([]recipientInfo, len(recipients))
    for i, recipient := range recipients {
        encrypted, err := keyEncrypt.Encrypt(key, recipient.PublicKey)
        if err != nil {
            return nil, err
        }

        ias, err := cert2issuerAndSerial(recipient)
        if err != nil {
            return nil, err
        }

        info := recipientInfo{
            Version:               0,
            IssuerAndSerialNumber: ias,
            KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
                Algorithm: keyEncrypt.OID(),
            },
            EncryptedKey: encrypted,
        }
        recipientInfos[i] = info
    }

    // Prepare envelope content
    envelope := envelopedData{
        EncryptedContentInfo: *eci,
        Version:              0,
        RecipientInfos:       recipientInfos,
    }
    innerContent, err := asn1.Marshal(envelope)
    if err != nil {
        return nil, err
    }

    // Prepare outer payload structure
    wrapper := contentInfo{
        ContentType: oidEnvelopedData,
        Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
    }

    return asn1.Marshal(wrapper)
}

// EncryptUsingPSK creates and returns an encrypted data PKCS7 structure,
// encrypted using caller provided pre-shared secret.
func EncryptUsingPSK(content []byte, key []byte, cipher Cipher) ([]byte, error) {
    var eci *encryptedContentInfo
    var err error

    if key == nil {
        return nil, ErrPSKNotProvided
    }

    encrypted, paramBytes, err := cipher.Encrypt(key, content)
    if err != nil {
        return nil, err
    }

    eci = &encryptedContentInfo{
        ContentType: oidData,
        ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
            Algorithm: cipher.OID(),
            Parameters: asn1.RawValue{
                FullBytes: paramBytes,
            },
        },
        EncryptedContent: marshalEncryptedContent(encrypted),
    }

    // Prepare encrypted-data content
    ed := encryptedData{
        Version:              0,
        EncryptedContentInfo: *eci,
    }
    innerContent, err := asn1.Marshal(ed)
    if err != nil {
        return nil, err
    }

    // Prepare outer payload structure
    wrapper := contentInfo{
        ContentType: oidEncryptedData,
        Content:     asn1.RawValue{
            Class: 2,
            Tag: 0,
            IsCompound: true,
            Bytes: innerContent,
        },
    }

    return asn1.Marshal(wrapper)
}

func marshalEncryptedContent(content []byte) asn1.RawValue {
    asn1Content, _ := asn1.Marshal(content)
    return asn1.RawValue{
        Tag: 0,
        Class: 2,
        Bytes: asn1Content,
        IsCompound: true,
    }
}

func cert2issuerAndSerial(cert *x509.Certificate) (issuerAndSerial, error) {
    var ias issuerAndSerial
    // The issuer RDNSequence has to match exactly the sequence in the certificate
    // We cannot use cert.Issuer.ToRDNSequence() here since it mangles the sequence
    ias.IssuerName = asn1.RawValue{FullBytes: cert.RawIssuer}
    ias.SerialNumber = cert.SerialNumber

    return ias, nil
}
