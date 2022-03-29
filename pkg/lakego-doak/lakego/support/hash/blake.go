package hash

import (
    "encoding/hex"
    "golang.org/x/crypto/blake2b"
    "golang.org/x/crypto/blake2s"
)

// BLAKE2b_256 哈希值
func BLAKE2b_256(s string) string {
    sum := blake2b.Sum256([]byte(s))
    return hex.EncodeToString(sum[:])
}

// BLAKE2b_384 哈希值
func BLAKE2b_384(s string) string {
    sum := blake2b.Sum384([]byte(s))
    return hex.EncodeToString(sum[:])
}

// BLAKE2b_512 哈希值
func BLAKE2b_512(s string) string {
    sum := blake2b.Sum512([]byte(s))
    return hex.EncodeToString(sum[:])
}

// BLAKE2s_256 哈希值
func BLAKE2s_256(s string) string {
    sum := blake2s.Sum256([]byte(s))
    return hex.EncodeToString(sum[:])
}
