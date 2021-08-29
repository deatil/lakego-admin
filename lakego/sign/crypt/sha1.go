package crypt

import (
    "crypto/sha1"
    "encoding/hex"
)

// SHA1 哈希值
func SHA1(s string) string {
    sum := sha1.Sum([]byte(s))
    return hex.EncodeToString(sum[:])
}
