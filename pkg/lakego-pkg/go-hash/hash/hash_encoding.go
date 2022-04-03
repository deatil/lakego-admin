package hash

import (
    "encoding/hex"
    "encoding/base64"
)

// Base64 编码
func (this Hash) Base64Encode(src []byte) string {
    return base64.StdEncoding.EncodeToString(src)
}

// Base64 解码
func (this Hash) Base64Decode(s string) ([]byte, error) {
    return base64.StdEncoding.DecodeString(s)
}

// Hex 编码
func (this Hash) HexEncode(src []byte) string {
    return hex.EncodeToString(src)
}

// Hex 解码
func (this Hash) HexDecode(s string) ([]byte, error) {
    return hex.DecodeString(s)
}
