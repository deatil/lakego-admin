package hash

import (
    "golang.org/x/crypto/sha3"
)

// Shake128 哈希值
func (this Hash) Shake128() Hash {
    data := make([]byte, 64)
    sha3.ShakeSum128(data, this.data)

    this.data = data

    return this
}

// Shake256 哈希值
func (this Hash) Shake256() Hash {
    data := make([]byte, 64)
    sha3.ShakeSum256(data, this.data)

    this.data = data

    return this
}
