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

// ====================

// Hex
func (this Encoding) FromHexString(data string) Encoding {
    this.data, this.Error = hex.DecodeString(data)

    return this
}

// Hex
func FromHexString(data string) Encoding {
    return defaultEncode.FromHexString(data)
}

// 输出 Hex
func (this Encoding) ToHexString() string {
    return hex.EncodeToString(this.data)
}
