package tool

import (
    "strings"
    "encoding/hex"
    "encoding/base64"
)

var (
    defaultEncoding = NewEncoding()
)

// 构造函数
func NewEncoding() Encoding {
    return Encoding{}
}

/**
 * 编码
 *
 * @create 2022-4-17
 * @author deatil
 */
type Encoding struct{}

// Base64 编码
func (this Encoding) Base64Encode(src []byte) string {
    return base64.StdEncoding.EncodeToString(src)
}

func Base64Encode(src []byte) string {
    return defaultEncoding.Base64Encode(src)
}

// Base64 解码
func (this Encoding) Base64Decode(s string) ([]byte, error) {
    return base64.StdEncoding.DecodeString(s)
}

func Base64Decode(s string) ([]byte, error) {
    return defaultEncoding.Base64Decode(s)
}

// Hex 编码
func (this Encoding) HexEncode(src []byte) string {
    return hex.EncodeToString(src)
}

func HexEncode(src []byte) string {
    return defaultEncoding.HexEncode(src)
}

// Hex 解码
func (this Encoding) HexDecode(s string) ([]byte, error) {
    return hex.DecodeString(s)
}

func HexDecode(s string) ([]byte, error) {
    return defaultEncoding.HexDecode(s)
}

// 补码
func (this Encoding) HexPadding(text string, size int) string {
    if size < 1 {
        return text
    }

    n := len(text)

    if n == size {
        return text
    }

    if n < size {
        return strings.Repeat("0", size-n) + text
    }

    return text[n-size:]
}

func HexPadding(text string, size int) string {
    return defaultEncoding.HexPadding(text, size)
}
