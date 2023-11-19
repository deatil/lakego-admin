package pkcs12

import (
    "errors"
    "crypto/sha1"
    "crypto/x509"
    "encoding/hex"
    "encoding/json"
    "encoding/asn1"
)

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
        return errors.New("pkcs12: trailing data found")
    }

    return nil
}
