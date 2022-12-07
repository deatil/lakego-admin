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
