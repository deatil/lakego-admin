package enveloped

import (
    "io"
    "fmt"
    "bytes"
    "errors"
    "math/big"
    "crypto"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/ber"
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

type Enveloped struct {}

func NewEnveloped() Enveloped {
    return Enveloped{}
}

// 加密
func (this Enveloped) Encrypt(rand io.Reader, content []byte, recipients []*x509.Certificate, opts ...Opts) ([]byte, error) {
    var eci *encryptedContentInfo
    var key []byte
    var err error

    opt := &DefaultOpts
    if len(opts) > 0 {
        opt = &opts[0]
    }

    cipher := opt.Cipher
    if cipher == nil {
        return nil, errors.New("go-cryptobin/pkcs12: failed to encrypt PEM: unknown opts cipher")
    }

    keyEncrypt := opt.KeyEncrypt
    if keyEncrypt == nil {
        return nil, errors.New("go-cryptobin/pkcs12: unknown opts keyEncrypt")
    }

    // 生成密钥
    key = make([]byte, cipher.KeySize())
    if _, err := io.ReadFull(rand, key); err != nil {
        return nil, errors.New("go-cryptobin/pkcs12: cannot generate key: " + err.Error())
    }

    encrypted, paramBytes, err := cipher.Encrypt(rand, key, content)
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
        EncryptedContent: this.marshalEncryptedContent(encrypted),
    }

    // Prepare each recipient's encrypted cipher key
    recipientInfos := make([]recipientInfo, len(recipients))
    for i, recipient := range recipients {
        encrypted, err := keyEncrypt.Encrypt(key, recipient.PublicKey)
        if err != nil {
            return nil, err
        }

        ias, err := this.cert2issuerAndSerial(recipient)
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

// 解析
func (this Enveloped) Decrypt(data []byte, cert *x509.Certificate, pkey crypto.PrivateKey) ([]byte, error) {
    info, contentType, err := this.parseData(data)
    if err != nil {
        return nil, err
    }

    if !contentType.Equal(oidEnvelopedData) {
        return nil, errors.New("go-cryptobin/pkcs12: contentType error")
    }

    var endata envelopedData
    if _, err := asn1.Unmarshal(info, &endata); err != nil {
        return nil, err
    }

    recipient := this.selectRecipientForCertificate(endata.RecipientInfos, cert)
    if recipient.EncryptedKey == nil {
        return nil, errors.New("go-cryptobin/pkcs12: no enveloped recipient for provided certificate")
    }

    keyEncrypt, err := this.parseKeyEncrypt(recipient.KeyEncryptionAlgorithm)
    if err != nil {
        return nil, err
    }

    contentKey, err := keyEncrypt.Decrypt(recipient.EncryptedKey, pkey)
    if err != nil {
        return nil, err
    }

    return this.encryptedContentInfoDecrypt(endata.EncryptedContentInfo, contentKey)
}

func (this Enveloped) marshalEncryptedContent(content []byte) asn1.RawValue {
    asn1Content, _ := asn1.Marshal(content)
    return asn1.RawValue{
        Tag: 0,
        Class: 2,
        Bytes: asn1Content,
        IsCompound: true,
    }
}

func (this Enveloped) cert2issuerAndSerial(cert *x509.Certificate) (issuerAndSerial, error) {
    var ias issuerAndSerial
    // The issuer RDNSequence has to match exactly the sequence in the certificate
    // We cannot use cert.Issuer.ToRDNSequence() here since it mangles the sequence
    ias.IssuerName = asn1.RawValue{FullBytes: cert.RawIssuer}
    ias.SerialNumber = cert.SerialNumber

    return ias, nil
}

func (this Enveloped) encryptedContentInfoDecrypt(eci encryptedContentInfo, key []byte) ([]byte, error) {
    // EncryptedContent can either be constructed of multple OCTET STRINGs
    // or _be_ a tagged OCTET STRING
    var cyphertext []byte
    if eci.EncryptedContent.IsCompound {
        // Complex case to concat all of the children OCTET STRINGs
        var buf bytes.Buffer
        cypherbytes := eci.EncryptedContent.Bytes
        for {
            var part []byte
            cypherbytes, _ = asn1.Unmarshal(cypherbytes, &part)
            buf.Write(part)
            if cypherbytes == nil {
                break
            }
        }
        cyphertext = buf.Bytes()
    } else {
        // Simple case, the bytes _are_ the cyphertext
        cyphertext = eci.EncryptedContent.Bytes
    }

    cipher, cipherParams, err := this.parseEncryptionScheme(eci.ContentEncryptionAlgorithm)
    if err != nil {
        return nil, err
    }

    decryptedKey, err := cipher.Decrypt(key, cipherParams, cyphertext)
    if err != nil {
        return nil, err
    }

    return decryptedKey, nil
}

func (this Enveloped) parseKeyEncrypt(keyEncrypt pkix.AlgorithmIdentifier) (KeyEncrypt, error) {
    oid := keyEncrypt.Algorithm.String()

    fn, ok := keyens[oid]
    if !ok {
        return nil, fmt.Errorf("unsupported KDF (OID: %s)", oid)
    }

    newFunc := fn()

    return newFunc, nil
}

func (this Enveloped) parseEncryptionScheme(encryptionScheme pkix.AlgorithmIdentifier) (Cipher, []byte, error) {
    newCipher, err := GetCipher(encryptionScheme)
    if err != nil {
        oid := encryptionScheme.Algorithm.String()
        return nil, nil, fmt.Errorf("go-cryptobin/pkcs12: unsupported cipher (OID: %s)", oid)
    }

    params := encryptionScheme.Parameters.FullBytes

    return newCipher, params, nil
}

// Parse decodes a DER encoded package
func (this Enveloped) parseData(data []byte) ([]byte, asn1.ObjectIdentifier, error) {
    if len(data) == 0 {
        return nil, asn1.ObjectIdentifier{}, errors.New("input data is empty")
    }

    der, err := ber.Ber2der(data)
    if err != nil {
        return nil, asn1.ObjectIdentifier{}, err
    }

    var info contentInfo
    rest, err := asn1.Unmarshal(der, &info)
    if len(rest) > 0 {
        err = asn1.SyntaxError{Msg: "trailing data"}
        return nil, asn1.ObjectIdentifier{}, err
    }

    content := info.Content.Bytes
    contentType := info.ContentType

    return content, contentType, nil
}

func (this Enveloped) selectRecipientForCertificate(recipients []recipientInfo, cert *x509.Certificate) recipientInfo {
    for _, recp := range recipients {
        if this.isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
            return recp
        }
    }

    return recipientInfo{}
}

func (this Enveloped) isCertMatchForIssuerAndSerial(cert *x509.Certificate, ias issuerAndSerial) bool {
    return cert.SerialNumber.Cmp(ias.SerialNumber) == 0 && bytes.Equal(cert.RawIssuer, ias.IssuerName.FullBytes)
}
