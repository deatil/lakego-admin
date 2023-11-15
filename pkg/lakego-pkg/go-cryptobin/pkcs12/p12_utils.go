package pkcs12

import (
    "encoding/json"
)

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

// 返回数据
func (this PKCS12Attributes) ToArray() map[string]string {
    attrs := make(map[string]string)

    for _, attribute := range this.attributes {
        k, v, err := convertAttribute(&attribute)
        if err == errUnknownAttributeOID {
            continue
        }

        if err != nil {
            return map[string]string{}
        }

        attrs[k] = v
    }

    return attrs
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
    Data() any

    // Attrs
    Attrs() PKCS12Attributes

    // FriendlyName return the value of `friendlyName`
    // attribute if exists, otherwise it will return empty string
    FriendlyName() string
}

type SafeBagData struct {
    data  any
    attrs PKCS12Attributes
}

func NewSafeBagData(data any, attrs PKCS12Attributes) SafeBagData {
    return SafeBagData{
        attrs: attrs,
        data:  data,
    }
}

func NewSafeBagDataWithAttrs(data any, attrs []PKCS12Attribute) SafeBagData {
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

func (this SafeBagData) Data() any {
    return this.data
}

func (this SafeBagData) FriendlyName() string {
    data := this.Attributes()

    return data["friendlyName"]
}
