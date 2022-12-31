package encoding

import (
    "bytes"
)

var encode Encoding

// 初始化
func init() {
    encode = NewEncoding()
}

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
    return encode.FromBytes(data)
}

// 字符
func FromString(data string) Encoding {
    return encode.FromString(data)
}

// Base32
func FromBase32String(data string) Encoding {
    return encode.FromBase32String(data)
}

// Base32
func FromBase32HexString(data string) Encoding {
    return encode.FromBase32HexString(data)
}

// Base32
func FromBase32EncoderString(data string, encoder string) Encoding {
    return encode.FromBase32EncoderString(data, encoder)
}

// Base45
func FromBase45String(data string) Encoding {
    return encode.FromBase45String(data)
}

// Base58
func FromBase58String(data string) Encoding {
    return encode.FromBase58String(data)
}

// Base64
func FromBase64String(data string) Encoding {
    return encode.FromBase64String(data)
}

// Base64
func FromBase64URLString(data string) Encoding {
    return encode.FromBase64URLString(data)
}

// Base64
func FromBase64RawString(data string) Encoding {
    return encode.FromBase64RawString(data)
}

// FromBase64RawURLString
func FromBase64RawURLString(data string) Encoding {
    return encode.FromBase64RawURLString(data)
}

// FromBase64SegmentString
func FromBase64SegmentString(data string) Encoding {
    return encode.FromBase64SegmentString(data)
}

// FromBase64EncoderString
func FromBase64EncoderString(data string, encoder string) Encoding {
    return encode.FromBase64EncoderString(data, encoder)
}

// Base85
func FromBase85String(data string) Encoding {
    return encode.FromBase85String(data)
}

// Base2
func FromBase2String(data string) Encoding {
    return encode.FromBase2String(data)
}

// Base16
func FromBase16String(data string) Encoding {
    return encode.FromBase16String(data)
}

// Basex62
func FromBasex62String(data string) Encoding {
    return encode.FromBasex62String(data)
}

// FromBasexEncoderString
func FromBasexEncoderString(data string, encoder string) Encoding {
    return encode.FromBasexEncoderString(data, encoder)
}

// Base62
func FromBase62String(data string) Encoding {
    return encode.FromBase62String(data)
}

// Base91
func FromBase91String(data string) Encoding {
    return encode.FromBase91String(data)
}

// Base100
func FromBase100String(data string) Encoding {
    return encode.FromBase100String(data)
}

// MorseITU
func FromMorseITUString(data string) Encoding {
    return encode.FromMorseITUString(data)
}

// Hex
func FromHexString(data string) Encoding {
    return encode.FromHexString(data)
}

// Hex
func FromBytesBuffer(data *bytes.Buffer) Encoding {
    return encode.FromBytesBuffer(data)
}

// Hex
func FromConvert(data any, base int, bitSize ...int) Encoding {
    return encode.FromConvert(data, base, bitSize...)
}

// 二进制
func FromConvertBin(data string) Encoding {
    return encode.FromConvertBin(data)
}

// 八进制
func FromConvertOct(data string) Encoding {
    return encode.FromConvertOct(data)
}

// 十进制
func FromConvertDec(data int64) Encoding {
    return encode.FromConvertDec(data)
}

// 十进制字符
func FromConvertDecString(data string) Encoding {
    return encode.FromConvertDecString(data)
}

// 十六进制
func FromConvertHex(data string) Encoding {
    return encode.FromConvertHex(data)
}

// Gob
func ForGob(data any) Encoding {
    return encode.ForGob(data)
}

// Xml
func ForXML(data any) Encoding {
    return encode.ForXML(data)
}

// JSON
func ForJSON(data any) Encoding {
    return encode.ForJSON(data)
}

// Binary
func ForBinary(data any) Encoding {
    return encode.ForBinary(data)
}

// Csv
func ForCsv(data [][]string) Encoding {
    return encode.ForCsv(data)
}

// Asn1
func ForAsn1(data any, params ...string) Encoding {
    return encode.ForAsn1(data, params...)
}

// ForSerialize
func ForSerialize(data any) Encoding {
    return encode.ForSerialize(data)
}
