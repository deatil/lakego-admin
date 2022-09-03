package encoding

import (
    "bytes"
)

// 构造函数
func NewEncoding() Encoding {
    return Encoding{}
}

// 构造函数
func New() Encoding {
    return NewEncoding()
}

// ==========

// 字节
func FromBytes(data []byte) Encoding {
    return New().FromBytes(data)
}

// 字符
func FromString(data string) Encoding {
    return New().FromString(data)
}

// Base32
func FromBase32String(data string) Encoding {
    return New().FromBase32String(data)
}

// Base32
func FromBase32HexString(data string) Encoding {
    return New().FromBase32HexString(data)
}

// Base32
func FromBase32EncoderString(data string, encoder string) Encoding {
    return New().FromBase32EncoderString(data, encoder)
}

// Base58
func FromBase58String(data string) Encoding {
    return New().FromBase58String(data)
}

// Base64
func FromBase64String(data string) Encoding {
    return New().FromBase64String(data)
}

// Base64
func FromBase64URLString(data string) Encoding {
    return New().FromBase64URLString(data)
}

// Base64
func FromBase64RawString(data string) Encoding {
    return New().FromBase64RawString(data)
}

// FromBase64RawURLString
func FromBase64RawURLString(data string) Encoding {
    return New().FromBase64RawURLString(data)
}

// FromBase64SegmentString
func FromBase64SegmentString(data string) Encoding {
    return New().FromBase64SegmentString(data)
}

// FromBase64EncoderString
func FromBase64EncoderString(data string, encoder string) Encoding {
    return New().FromBase64EncoderString(data, encoder)
}

// Base85
func FromBase85String(data string) Encoding {
    return New().FromBase85String(data)
}

// Base2
func FromBase2String(data string) Encoding {
    return New().FromBase2String(data)
}

// Base16
func FromBase16String(data string) Encoding {
    return New().FromBase16String(data)
}

// Base62
func FromBase62String(data string) Encoding {
    return New().FromBase62String(data)
}

// FromBasexEncoderString
func FromBasexEncoderString(data string, encoder string) Encoding {
    return New().FromBasexEncoderString(data, encoder)
}

// Hex
func FromHexString(data string) Encoding {
    return New().FromHexString(data)
}

// Hex
func FromBytesBuffer(data *bytes.Buffer) Encoding {
    return New().FromBytesBuffer(data)
}

// Hex
func FromConvert(data any, base int, bitSize ...int) Encoding {
    return New().FromConvert(data, base, bitSize...)
}

// 二进制
func FromConvertBin(data string) Encoding {
    return New().FromConvertBin(data)
}

// 八进制
func FromConvertOct(data string) Encoding {
    return New().FromConvertOct(data)
}

// 十进制
func FromConvertDec(data int64) Encoding {
    return New().FromConvertDec(data)
}

// 十进制字符
func FromConvertDecString(data string) Encoding {
    return New().FromConvertDecString(data)
}

// 十六进制
func FromConvertHex(data string) Encoding {
    return New().FromConvertHex(data)
}

// Gob
func ForGob(data any) Encoding {
    return New().ForGob(data)
}

// Xml
func ForXML(data any) Encoding {
    return New().ForXML(data)
}

// JSON
func ForJSON(data any) Encoding {
    return New().ForJSON(data)
}

// Binary
func ForBinary(data any) Encoding {
    return New().ForBinary(data)
}

// Csv
func ForCsv(data [][]string) Encoding {
    return New().ForCsv(data)
}

// Asn1
func ForAsn1(data any, params ...string) Encoding {
    return New().ForAsn1(data, params...)
}

// ForSerialize
func ForSerialize(data any) Encoding {
    return New().ForSerialize(data)
}
