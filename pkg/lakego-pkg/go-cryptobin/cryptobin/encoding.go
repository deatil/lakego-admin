package cryptobin

import (
    "strings"
    "encoding/hex"
    "encoding/base64"
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

// Base64 解码
func (this Encoding) Base64Decode(s string) ([]byte, error) {
    return base64.StdEncoding.DecodeString(s)
}

// Hex 编码
func (this Encoding) HexEncode(src []byte) string {
    return hex.EncodeToString(src)
}

// Hex 解码
func (this Encoding) HexDecode(s string) ([]byte, error) {
    return hex.DecodeString(s)
}

// 补码
func (this Encoding) RSHexPadding(text string) string {
    n := len(text)

    if n == 64 {
        return text
    }

    if n < 64 {
        return strings.Repeat("0", 64-n) + text
    }

    return text[n-64:]
}
