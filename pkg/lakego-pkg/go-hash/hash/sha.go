package hash

import (
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/hex"
)

// SHA1 哈希值
func SHA1(s string) string {
    sum := sha1.Sum([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA1 哈希值
func (this Hash) SHA1() Hash {
    return this.UseHash(sha1.New)
}

// SHA224 哈希值
func SHA224(s string) string {
    sum := sha256.Sum224([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA224 哈希值
func (this Hash) SHA224() Hash {
    return this.UseHash(sha256.New224)
}

// SHA256 哈希值
func SHA256(s string) string {
    sum := sha256.Sum256([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA256 哈希值
func (this Hash) SHA256() Hash {
    return this.UseHash(sha256.New)
}

// SHA384 哈希值
func SHA384(s string) string {
    sum := sha512.Sum384([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA384 哈希值
func (this Hash) SHA384() Hash {
    return this.UseHash(sha512.New384)
}

// SHA512 哈希值
func SHA512(s string) string {
    sum := sha512.Sum512([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA512 哈希值
func (this Hash) SHA512() Hash {
    return this.UseHash(sha512.New)
}

// SHA512_224 哈希值
func SHA512_224(s string) string {
    sum := sha512.Sum512_224([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA512_224 哈希值
func (this Hash) SHA512_224() Hash {
    return this.UseHash(sha512.New512_224)
}

// SHA512_256 哈希值
func SHA512_256(s string) string {
    sum := sha512.Sum512_256([]byte(s))
    return hex.EncodeToString(sum[:])
}

// SHA512_256 哈希值
func (this Hash) SHA512_256() Hash {
    return this.UseHash(sha512.New512_256)
}
