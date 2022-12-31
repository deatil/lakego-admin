package encoding

import (
    "github.com/deatil/go-encoding/base58"
)

// Base58 编码
func Base58Encode(str string) string {
    return base58.Encode([]byte(str))
}

// Base58 解码
func Base58Decode(str string) string {
    decoded := base58.Decode(str)

    return string(decoded)
}

// ====================

// Base58
func (this Encoding) FromBase58String(data string) Encoding {
    data = Base58Decode(data)

    this.data = []byte(data)

    return this
}

// Base58
func FromBase58String(data string) Encoding {
    return defaultEncode.FromBase58String(data)
}

// 输出 Base58
func (this Encoding) ToBase58String() string {
    return Base58Encode(string(this.data))
}
