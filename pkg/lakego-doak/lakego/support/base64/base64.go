package base64

import (
    "strings"
    "encoding/base64"
)

// 加密
func Encode(str string) string {
    newStr := base64.StdEncoding.EncodeToString([]byte(str))
    return newStr
}

// 解密
func Decode(str string) string {
    newStr, err := base64.StdEncoding.DecodeString(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// URL 加密
func URLEncode(str string) string {
    newStr := base64.URLEncoding.EncodeToString([]byte(str))
    return newStr
}

// URL 解密
func URLDecode(str string) string {
    newStr, err := base64.URLEncoding.DecodeString(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// Raw 加密，无填充编码
func RawEncode(str string) string {
    newStr := base64.RawStdEncoding.EncodeToString([]byte(str))
    return newStr
}

// Raw 解密，无填充编码
func RawDecode(str string) string {
    newStr, err := base64.RawStdEncoding.DecodeString(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// RawURL 加密，无填充编码
func RawURLEncode(str string) string {
    newStr := base64.RawURLEncoding.EncodeToString([]byte(str))
    return newStr
}

// RawURL 解密，无填充编码
func RawURLDecode(str string) string {
    newStr, err := base64.RawURLEncoding.DecodeString(str)
    if err != nil {
        return ""
    }

    return string(newStr)
}

// URL
func EncodeSegment(seg string) string {
    return strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(seg)), "=")
}

// URL
func DecodeSegment(seg string) string {
    if l := len(seg) % 4; l > 0 {
        seg += strings.Repeat("=", 4-l)
    }

    newStr, err := base64.RawStdEncoding.DecodeString(seg)
    if err != nil {
        return ""
    }

    return string(newStr)
}

