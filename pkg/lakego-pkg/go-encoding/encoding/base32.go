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
    newStr := base32.StdEncoding.EncodeToString([]byte(str))
    return newStr
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
    newStr := base32.HexEncoding.EncodeToString([]byte(str))
    return newStr
}

// Base32Hex 解码
func Base32HexDecode(str string) string {
    newStr, err := base32.HexEncoding.DecodeString(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}
