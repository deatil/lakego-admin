package hash

import (
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "encoding/hex"

    "github.com/deatil/lakego-doak/lakego/support/str"
)

// MD5 哈希值
func MD5(s string) string {
    sum := md5.Sum(str.S(s).Bytes())
    return hex.EncodeToString(sum[:])
}

// SHA1 哈希值
func SHA1(s string) string {
    sum := sha1.Sum(str.S(s).Bytes())
    return hex.EncodeToString(sum[:])
}

// SHA256 哈希值
func SHA256(s string) string {
    sum := sha256.Sum256(str.S(s).Bytes())
    return hex.EncodeToString(sum[:])
}
