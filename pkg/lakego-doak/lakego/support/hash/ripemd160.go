package hash

import (
    "encoding/hex"
    "golang.org/x/crypto/ripemd160"
)

// Ripemd160 哈希值
func Ripemd160(s string) string {
    m := ripemd160.New()
    m.Write([]byte(s))
    return hex.EncodeToString(m.Sum(nil))
}
