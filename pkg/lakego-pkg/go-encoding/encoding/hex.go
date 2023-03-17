package encoding

import (
    "encoding/hex"
)

// Hex
func (this Encoding) HexDecode() Encoding {
    data := string(this.data)
    this.data, this.Error = hex.DecodeString(data)

    return this
}

// 输出 Hex
func (this Encoding) HexEncode() Encoding {
    data := hex.EncodeToString(this.data)
    this.data = []byte(data)

    return this
}
