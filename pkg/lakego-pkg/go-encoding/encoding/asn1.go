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
