package pkcs12

import (
    "io"
    "bytes"
    "errors"
    "encoding/asn1"
    "crypto/x509/pkix"
)

var (
    // see https://tools.ietf.org/html/rfc7292#appendix-D
    oidKeyBag                  = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 1})
    oidPKCS8ShroundedKeyBag    = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 2})
    oidCertBag                 = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 3})
    oidCRLBag                  = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 4})
    oidSecretBag               = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 5})
    oidSafeContentsBag         = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 10, 1, 6})

    oidCertTypeX509Certificate = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 22, 1})
    oidCertTypeSdsiCertificate = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 22, 2})

    oidCertTypeX509CRL         = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 23, 1})
)

var (
    oidDataContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
    oidEnvelopedDataContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
    oidEncryptedDataContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

    oidFriendlyName     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
    oidLocalKeyID       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
    oidMicrosoftCSPName = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 17, 1}

    oidJavaTrustStore      = asn1.ObjectIdentifier{2, 16, 840, 1, 113894, 746875, 1, 1}
    oidAnyExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
)

var (
    errUnknownAttributeOID = errors.New("pkcs12: unknown attribute OID")
)

// PEM block types
const (
    CertificateType = "CERTIFICATE"
    CRLType         = "X509 CRL"
    PrivateKeyType  = "PRIVATE KEY"
)

const (
    // PKCS12 系列
    PKCS12Version = 3
)

// Encode secret key in a pkcs8
// See ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn, RFC 5208,
// https://github.com/openjdk/jdk/blob/jdk8-b120/jdk/src/share/classes/sun/security/pkcs12/PKCS12KeyStore.java#L613,
// https://github.com/openjdk/jdk/blob/jdk9-b94/jdk/src/java.base/share/classes/sun/security/pkcs12/PKCS12KeyStore.java#L624
// and https://github.com/golang/go/blob/master/src/crypto/x509/pkcs8.go
type pkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
}

type PfxPdu struct {
    Version  int
    AuthSafe ContentInfo
    MacData  MacData `asn1:"optional"`
}

type ContentInfo struct {
    ContentType asn1.ObjectIdentifier
    Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type EncryptedData struct {
    Version              int
    EncryptedContentInfo EncryptedContentInfo
}

type EncryptedContentInfo struct {
    ContentType                asn1.ObjectIdentifier
    ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
    EncryptedContent           []byte `asn1:"tag:0,optional"`
}

func (this EncryptedContentInfo) Algorithm() pkix.AlgorithmIdentifier {
    return this.ContentEncryptionAlgorithm
}

func (this EncryptedContentInfo) Data() []byte {
    return this.EncryptedContent
}

type PKCS12Attribute struct {
    Id    asn1.ObjectIdentifier
    Value asn1.RawValue `asn1:"set"`
}

type SafeBag struct {
    Id         asn1.ObjectIdentifier
    Value      asn1.RawValue     `asn1:"tag:0,explicit"`
    Attributes []PKCS12Attribute `asn1:"set,optional"`
}

func (bag *SafeBag) hasAttribute(id asn1.ObjectIdentifier) bool {
    for _, attr := range bag.Attributes {
        if attr.Id.Equal(id) {
            return true
        }
    }

    return false
}

// DefaultPassword is the string "cryptobin", a commonly-used password for
// PKCS#12 files. Due to the weak encryption used by PKCS#12, it is
// RECOMMENDED that you use DefaultPassword when encoding PKCS#12 files,
// and protect the PKCS#12 files using other means.
const DefaultPassword = "cryptobin"

// PKCS12 结构
type PKCS12 struct {
    // 私钥
    privateKey []byte

    // 证书
    cert []byte

    // 证书链
    caCerts [][]byte

    // 证书链带名称, 适配 JAVA
    trustStores []TrustStoreData

    // sdsi
    sdsiCert []byte

    // 证书移除列表
    crl []byte

    // 密钥
    secretKey []byte

    // localKeyId
    localKeyId []byte

    // 解析后数据
    parsedData map[string][]ISafeBagData

    // Enveloped 加密配置
    envelopedOpts *EnvelopedOpts
}

func NewPKCS12() *PKCS12 {
    return &PKCS12{
        caCerts:     make([][]byte, 0),
        trustStores: make([]TrustStoreData, 0),
        parsedData:  make(map[string][]ISafeBagData),
    }
}

func (this *PKCS12) WithLocalKeyId(id []byte) *PKCS12 {
    this.localKeyId = id

    return this
}

func (this *PKCS12) WithEnvelopedOpts(opts EnvelopedOpts) *PKCS12 {
    this.envelopedOpts = &opts

    return this
}

func (this *PKCS12) String() string {
    return "PKCS12"
}

// LoadPKCS12FromReader loads the key store from the specified file.
func LoadPKCS12FromReader(reader io.Reader, password string) (*PKCS12, error) {
    buf := bytes.NewBuffer(nil)

    // 保存
    if _, err := io.Copy(buf, reader); err != nil {
        return nil, err
    }

    return LoadPKCS12FromBytes(buf.Bytes(), password)
}

// LoadPKCS12FromBytes loads the key store from the bytes data.
func LoadPKCS12FromBytes(data []byte, password string) (*PKCS12, error) {
    pkcs12 := NewPKCS12()

    _, err := pkcs12.Parse(data, password)
    if err != nil {
        return nil, err
    }

    return pkcs12, err
}

// 别名
var LoadPKCS12      = LoadPKCS12FromBytes
var NewPKCS12Encode = NewPKCS12
