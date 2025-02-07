package encoding

import (
    "encoding/hex"
)

// Hex Decode
func (this Encoding) HexDecode() Encoding {
    data := string(this.data)
    this.data, this.Error = hex.DecodeString(data)

    return this
}

// Hex Encode
func (this Encoding) HexEncode() Encoding {
    data := hex.EncodeToString(this.data)
    this.data = []byte(data)

    return this
}
