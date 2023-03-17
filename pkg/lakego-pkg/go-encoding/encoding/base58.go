package encoding

import (
    "github.com/deatil/go-encoding/base58"
)

// Base58
func (this Encoding) Base58Decode() Encoding {
    this.data = base58.Decode(string(this.data))

    return this
}

// 编码 Base58
func (this Encoding) Base58Encode() Encoding {
    data := base58.Encode(this.data)
    this.data = []byte(data)

    return this
}
