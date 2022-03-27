package encoding

import (
    "encoding/hex"
)

// Hex 编码
func HexEncode(src string) string {
    return hex.EncodeToString([]byte(src))
}

// Hex 解码
func HexDecode(s string) string {
    data, _ := hex.DecodeString(s)
    return string(data)
}
