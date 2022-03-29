package hash

import (
    "encoding/hex"
    "golang.org/x/crypto/sha3"
)

// SHA3_224 哈希值
func SHA3_224(s string) string {
    sum := sha3.Sum224([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA3_256 哈希值
func SHA3_256(s string) string {
    sum := sha3.Sum256([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA3_384 哈希值
func SHA3_384(s string) string {
    sum := sha3.Sum384([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA3_512 哈希值
func SHA3_512(s string) string {
    sum := sha3.Sum512([]byte(s))
    return hex.EncodeToString(sum[:])
}
