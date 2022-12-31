package encoding

import (
    "strings"
    "encoding/base64"
)

var (
    // 自定义编码表
    // newStr := NewBase64Encoding(encoder string).WithPadding(NoPadding).EncodeToString(src []byte)
    // newStr, err := NewBase64Encoding(encoder string).WithPadding(NoPadding).DecodeString(src string)
    NewBase64Encoding = base64.NewEncoding
)

// 加密
func Base64Encode(str string) string {
    return base64.StdEncoding.EncodeToString([]byte(str))
}

// 解密
func Base64Decode(str string) string {
    newStr, err := base64.StdEncoding.DecodeString(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// URL 加密
func Base64URLEncode(str string) string {
    return base64.URLEncoding.EncodeToString([]byte(str))
}

// URL 解密
func Base64URLDecode(str string) string {
    newStr, err := base64.URLEncoding.DecodeString(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// Raw 加密，无填充编码
func Base64RawEncode(str string) string {
    return base64.RawStdEncoding.EncodeToString([]byte(str))
}

// Raw 解密，无填充编码
func Base64RawDecode(str string) string {
    newStr, err := base64.RawStdEncoding.DecodeString(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// RawURL 加密，无填充编码
func Base64RawURLEncode(str string) string {
    return base64.RawURLEncoding.EncodeToString([]byte(str))
}

// RawURL 解密，无填充编码
func Base64RawURLDecode(str string) string {
    newStr, err := base64.RawURLEncoding.DecodeString(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// URL
func Base64EncodeSegment(seg string) string {
    return strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(seg)), "=")
}

// URL
func Base64DecodeSegment(seg string) string {
    if l := len(seg) % 4; l > 0 {
        seg += strings.Repeat("=", 4-l)
    }

    newStr, err := base64.RawStdEncoding.DecodeString(seg)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// ====================

// Base64
func (this Encoding) FromBase64String(data string) Encoding {
    this.data, this.Error = base64.StdEncoding.DecodeString(data)

    return this
}

// Base64
func FromBase64String(data string) Encoding {
    return defaultEncode.FromBase64String(data)
}

// Base64URL
func (this Encoding) FromBase64URLString(data string) Encoding {
    this.data, this.Error = base64.URLEncoding.DecodeString(data)

    return this
}

// Base64
func FromBase64URLString(data string) Encoding {
    return defaultEncode.FromBase64URLString(data)
}

// Base64Raw
func (this Encoding) FromBase64RawString(data string) Encoding {
    this.data, this.Error = base64.RawStdEncoding.DecodeString(data)

    return this
}

// Base64
func FromBase64RawString(data string) Encoding {
    return defaultEncode.FromBase64RawString(data)
}

// Base64RawURL
func (this Encoding) FromBase64RawURLString(data string) Encoding {
    this.data, this.Error = base64.RawURLEncoding.DecodeString(data)

    return this
}

// FromBase64RawURLString
func FromBase64RawURLString(data string) Encoding {
    return defaultEncode.FromBase64RawURLString(data)
}

// Base64Segment
func (this Encoding) FromBase64SegmentString(data string, paddingAllowed ...bool) Encoding {
    if len(paddingAllowed) > 0 && paddingAllowed[0] {
        if l := len(data) % 4; l > 0 {
            data += strings.Repeat("=", 4-l)
        }

        this.data, this.Error = base64.URLEncoding.DecodeString(data)

        return this
    }

    this.data, this.Error = base64.RawURLEncoding.DecodeString(data)

    return this
}

// FromBase64SegmentString
func FromBase64SegmentString(data string) Encoding {
    return defaultEncode.FromBase64SegmentString(data)
}

// FromBase64EncoderString
func (this Encoding) FromBase64EncoderString(data string, encoder string) Encoding {
    this.data, this.Error = base64.NewEncoding(encoder).DecodeString(data)

    return this
}

// FromBase64EncoderString
func FromBase64EncoderString(data string, encode string) Encoding {
    return defaultEncode.FromBase64EncoderString(data, encode)
}

// ====================

// 输出 Base64
func (this Encoding) ToBase64String() string {
    return base64.StdEncoding.EncodeToString(this.data)
}

// 输出 Base64URL
func (this Encoding) ToBase64URLString() string {
    return base64.URLEncoding.EncodeToString(this.data)
}

// 输出 Base64Raw
func (this Encoding) ToBase64RawString() string {
    return base64.RawStdEncoding.EncodeToString(this.data)
}

// 输出 Base64RawURL
func (this Encoding) ToBase64RawURLString() string {
    return base64.RawURLEncoding.EncodeToString(this.data)
}

// 输出 Base64Segment
func (this Encoding) ToBase64SegmentString() string {
    return base64.RawURLEncoding.EncodeToString(this.data)
}

// 输出 Base64Encoder
func (this Encoding) ToBase64EncoderString(encoder string) string {
    return base64.NewEncoding(encoder).EncodeToString(this.data)
}
