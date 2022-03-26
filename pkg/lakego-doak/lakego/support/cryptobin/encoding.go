package cryptobin

import (
    "encoding/hex"
    "encoding/base64"
)

// Base64 编码
func (this Cryptobin) Base64Encode(src []byte) string {
    return base64.StdEncoding.EncodeToString(src)
}

// Base64 解码
func (this Cryptobin) Base64Decode(s string) ([]byte, error) {
    return base64.StdEncoding.DecodeString(s)
}

// Hex 编码
func (this Cryptobin) HexEncode(src []byte) string {
    return hex.EncodeToString(src)
}

// Hex 解码
func (this Cryptobin) HexDecode(s string) ([]byte, error) {
    return hex.DecodeString(s)
}
