package encoding

import (
    cryptobin_base58 "github.com/deatil/go-encoding/base58"
)

// Base58 编码
func Base58Encode(str string) string {
    return cryptobin_base58.Encode([]byte(str))
}

// Base58 解码
func Base58Decode(str string) string {
    decoded := cryptobin_base58.Decode(str)

    return string(decoded)
}
