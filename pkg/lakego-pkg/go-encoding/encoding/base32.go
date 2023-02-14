package encoding

import (
    "encoding/base32"
)

var (
    // 自定义编码表
    // newStr := NewBase32Encoding(encoder string).WithPadding(NoPadding).EncodeToString(src []byte)
    // newStr, err := NewBase32Encoding(encoder string).WithPadding(NoPadding).DecodeString(src string)
    NewBase32Encoding = base32.NewEncoding
)

// Base32 编码
func Base32Encode(str string) string {
    return base32.StdEncoding.EncodeToString([]byte(str))
}

// Base32 解码
func Base32Decode(str string) string {
    newStr, err := base32.StdEncoding.DecodeString(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// Base32Hex 编码
func Base32HexEncode(str string) string {
    return base32.HexEncoding.EncodeToString([]byte(str))
}

// Base32Hex 解码
func Base32HexDecode(str string) string {
    newStr, err := base32.HexEncoding.DecodeString(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// ====================

// Base32
func (this Encoding) FromBase32String(data string) Encoding {
    this.data, this.Error = base32.StdEncoding.DecodeString(data)

    return this
}

// Base32
func FromBase32String(data string) Encoding {
    return defaultEncode.FromBase32String(data)
}

// Base32Hex
func (this Encoding) FromBase32HexString(data string) Encoding {
    this.data, this.Error = base32.HexEncoding.DecodeString(data)

    return this
}

// Base32
func FromBase32HexString(data string) Encoding {
    return defaultEncode.FromBase32HexString(data)
}

// FromBase32EncoderString
func (this Encoding) FromBase32EncoderString(data string, encoder string) Encoding {
    this.data, this.Error = base32.NewEncoding(encoder).DecodeString(data)

    return this
}

// Base32
func FromBase32EncoderString(data string, encode string) Encoding {
    return defaultEncode.FromBase32EncoderString(data, encode)
}

// ====================

// 输出 Base32
func (this Encoding) ToBase32String() string {
    return base32.StdEncoding.EncodeToString(this.data)
}

// 输出 Base32Hex
func (this Encoding) ToBase32HexString() string {
    return base32.HexEncoding.EncodeToString(this.data)
}

// 输出 Base32Encoder
func (this Encoding) ToBase32EncoderString(encoder string) string {
    return base32.NewEncoding(encoder).EncodeToString(this.data)
}
