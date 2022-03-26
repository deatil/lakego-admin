package hash

import (
    "crypto/md5"
    "encoding/hex"
)

// MD5 哈希值
func MD5(s string) string {
    sum := md5.Sum([]byte(s))
    return hex.EncodeToString(sum[:])
}

// MD5 16位哈希值
func MD516(s string) string {
    data := MD5(s)
    return data[8:24]
}
