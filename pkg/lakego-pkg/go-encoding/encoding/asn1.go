package encoding

import (
    "encoding/asn1"
)

// Asn1 编码
func Asn1Encode(src any) ([]byte, error) {
    return asn1.Marshal(src)
}

// Asn1 编码
func Asn1EncodeWithParams(src any, params string) ([]byte, error) {
    return asn1.MarshalWithParams(src, params)
}

// Asn1 解码
func Asn1Decode(src []byte, val any) ([]byte, error) {
    return asn1.Unmarshal(src, val)
}

// Asn1 解码
func Asn1DecodeWithParams(src []byte, val any, params string) ([]byte, error) {
    return asn1.UnmarshalWithParams(src, val, params)
}

// ====================

// Asn1
func (this Encoding) ForAsn1(data any, params ...string) Encoding {
    if len(params) > 0 {
        this.data, this.Error = asn1.MarshalWithParams(data, params[0])
    } else {
        this.data, this.Error = asn1.Marshal(data)
    }

    return this
}

// Asn1
func ForAsn1(data any, params ...string) Encoding {
    return defaultEncode.ForAsn1(data, params...)
}

// Asn1 编码输出
func (this Encoding) Asn1To(val any, params ...string) ([]byte, error) {
    if len(params) > 0 {
        return asn1.UnmarshalWithParams(this.data, val, params[0])
    } else {
        return asn1.Unmarshal(this.data, val)
    }
}
