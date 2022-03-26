package hash

import (
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/hex"
    "golang.org/x/crypto/sha3"
)

// SHA1 哈希值
func SHA1(s string) string {
    sum := sha1.Sum([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA224 哈希值
func SHA224(s string) string {
    sum := sha256.Sum224([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA256 哈希值
func SHA256(s string) string {
    sum := sha256.Sum256([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA384 哈希值
func SHA384(s string) string {
    sum := sha512.Sum384([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA512 哈希值
func SHA512(s string) string {
    sum := sha512.Sum512([]byte(s))
    return hex.EncodeToString(sum[:])
}

// ==========

// SHA3224 哈希值
func SHA3224(s string) string {
    sum := sha3.Sum224([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA3256 哈希值
func SHA3256(s string) string {
    sum := sha3.Sum256([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA3384 哈希值
func SHA3384(s string) string {
    sum := sha3.Sum384([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA3512 哈希值
func SHA3512(s string) string {
    sum := sha3.Sum512([]byte(s))
    return hex.EncodeToString(sum[:])
}
