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
    newStr := base64.StdEncoding.EncodeToString([]byte(str))
    return newStr
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
    newStr := base64.URLEncoding.EncodeToString([]byte(str))
    return newStr
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
    newStr := base64.RawStdEncoding.EncodeToString([]byte(str))
    return newStr
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
    newStr := base64.RawURLEncoding.EncodeToString([]byte(str))
    return newStr
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

