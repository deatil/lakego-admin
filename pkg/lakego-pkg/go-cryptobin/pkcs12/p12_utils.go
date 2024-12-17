package pkcs12

import (
    "io"
    "errors"
    "crypto/sha1"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/hex"
    "encoding/json"
    "encoding/asn1"
)

var EnvelopedCipher = envelopedCipher{}

// envelopedCipher
type envelopedCipher struct {}

func (this envelopedCipher) OID() asn1.ObjectIdentifier {
    return asn1.ObjectIdentifier{}
}

func (this envelopedCipher) KeySize() int {
    return 0
}

func (this envelopedCipher) HasKeyLength() bool {
    return false
}

func (this envelopedCipher) NeedBmpPassword() bool {
    return false
}

func (this envelopedCipher) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, []byte, error) {
    return nil, nil, errors.New("error")
}

func (this envelopedCipher) Decrypt(key, params, ciphertext []byte) ([]byte, error) {
    return nil, errors.New("error")
}

// https://tools.ietf.org/html/rfc7292#section-4.2.5
// SecretBag ::= SEQUENCE {
//   secretTypeId   BAG-TYPE.&id ({SecretTypes}),
//   secretValue    [0] EXPLICIT BAG-TYPE.&Type ({SecretTypes}
//                     {@secretTypeId})
// }
type secretBag struct {
    SecretTypeID asn1.ObjectIdentifier
    SecretValue  []byte `asn1:"tag:0,explicit"`
}

type secretValue struct {
    AlgorithmIdentifier pkix.AlgorithmIdentifier
    EncryptedContent    []byte
}

func (this secretValue) Algorithm() pkix.AlgorithmIdentifier {
    return this.AlgorithmIdentifier
}

func (this secretValue) Data() []byte {
    return this.EncryptedContent
}

// TrustStoreData represents an entry in a Java TrustStore.
type TrustStoreData struct {
    Cert         []byte
    FriendlyName string
}

func NewTrustStoreData(cert *x509.Certificate, friendlyName string) TrustStoreData {
    return TrustStoreData{
        Cert: cert.Raw,
        FriendlyName: friendlyName,
    }
}

// 额外数据
type PKCS12Attributes struct {
    // 额外数据
    attributes []PKCS12Attribute
}

func NewPKCS12Attributes(attrs []PKCS12Attribute) PKCS12Attributes {
    return PKCS12Attributes{
        attributes: attrs,
    }
}

func NewPKCS12AttributesEmpty() PKCS12Attributes {
    return PKCS12Attributes{
        attributes: make([]PKCS12Attribute, 0),
    }
}

// 返回数据
func (this PKCS12Attributes) ToArray() map[string]string {
    attrs := make(map[string]string)

    for _, attribute := range this.attributes {
        k, v, err := convertAttribute(&attribute)
        if err != nil && err != errUnknownAttributeOID {
            continue
        }

        attrs[k] = v
    }

    return attrs
}

// 数据
func (this PKCS12Attributes) Attributes() []PKCS12Attribute {
    return this.attributes
}

// 判断
func (this PKCS12Attributes) HasAttr(name string) bool {
    attrs := this.ToArray()

    _, ok := attrs[name]
    if !ok {
        return false
    }

    return true
}

// 获取
func (this PKCS12Attributes) GetAttr(name string) string {
    attrs := this.ToArray()

    value, ok := attrs[name]
    if !ok {
        return ""
    }

    return value
}

// 验证签名数据
func (this PKCS12Attributes) Verify(data []byte) bool {
    attrs := this.ToArray()

    keyId, ok := attrs["localKeyId"]
    if !ok {
        return false
    }

    dataSha := sha1.Sum(data)
    dataHex := hex.EncodeToString(dataSha[:])

    return keyId == dataHex
}

// 键值列表
func (this PKCS12Attributes) Names() []string {
    attrs := this.ToArray()

    names := make([]string, 0)
    for name, _ := range attrs {
        names = append(names, name)
    }

    return names
}

// 返回字符
func (this PKCS12Attributes) String() string {
    data, _ := json.Marshal(this.ToArray())

    return string(data)
}

// SafeBagData
type ISafeBagData interface {
    // Attributes return the PKCS12AttrSet of the safe bag
    Attributes() map[string]string

    // Data
    Data() []byte

    // Attrs
    Attrs() PKCS12Attributes

    // FriendlyName return the value of `friendlyName`
    // attribute if exists, otherwise it will return empty string
    FriendlyName() string
}

type SafeBagData struct {
    data  []byte
    attrs PKCS12Attributes
}

func NewSafeBagData(data []byte, attrs PKCS12Attributes) SafeBagData {
    return SafeBagData{
        attrs: attrs,
        data:  data,
    }
}

func NewSafeBagDataWithAttrs(data []byte, attrs []PKCS12Attribute) SafeBagData {
    return SafeBagData{
        attrs: NewPKCS12Attributes(attrs),
        data:  data,
    }
}

func (this SafeBagData) Attrs() PKCS12Attributes {
    return this.attrs
}

func (this SafeBagData) Attributes() map[string]string {
    return this.attrs.ToArray()
}

func (this SafeBagData) Data() []byte {
    return this.data
}

func (this SafeBagData) FriendlyName() string {
    data := this.Attributes()

    return data["friendlyName"]
}

// unmarshal calls asn1.Unmarshal, but also returns an error if there is any
// trailing data after unmarshaling.
func unmarshal(in []byte, out any) error {
    trailing, err := asn1.Unmarshal(in, out)
    if err != nil {
        return err
    }

    if len(trailing) != 0 {
        return errors.New("go-cryptobin/pkcs12: trailing data found")
    }

    return nil
}

func convertAttribute(attribute *PKCS12Attribute) (key, value string, err error) {
    isString := false

    switch {
        case attribute.Id.Equal(oidFriendlyName):
            key = "friendlyName"
            isString = true
        case attribute.Id.Equal(oidLocalKeyID):
            key = "localKeyId"
        case attribute.Id.Equal(oidMicrosoftCSPName):
            // This key is chosen to match OpenSSL.
            key = "Microsoft CSP Name"
            isString = true
        case attribute.Id.Equal(oidJavaTrustStore):
            key = "javaTrustStore"

            storeOID := new(asn1.ObjectIdentifier)
            if _, err := asn1.Unmarshal(attribute.Value.Bytes, storeOID); err != nil {
                return "", "", err
            }

            value = (*storeOID).String()

            return
        default:
            key   = attribute.Id.String()
            value = hex.EncodeToString(attribute.Value.Bytes)
            err   = errUnknownAttributeOID

            return
    }

    if isString {
        if err := unmarshal(attribute.Value.Bytes, &attribute.Value); err != nil {
            return "", "", err
        }
        if value, err = decodeBMPString(attribute.Value.Bytes); err != nil {
            return "", "", err
        }
    } else {
        var id []byte
        if err := unmarshal(attribute.Value.Bytes, &id); err != nil {
            return "", "", err
        }

        value = hex.EncodeToString(id)
    }

    return key, value, nil
}
