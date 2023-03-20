package hash

import (
    "golang.org/x/crypto/sha3"
)

// Shake128 哈希值 num = 64
func (this Hash) Shake128(num int) Hash {
    data := make([]byte, num)
    sha3.ShakeSum128(data, this.data)

    this.data = data

    return this
}

// Shake256 哈希值 num = 64
func (this Hash) Shake256(num int) Hash {
    data := make([]byte, num)
    sha3.ShakeSum256(data, this.data)

    this.data = data

    return this
}

// CShake128 哈希值 num = 64
func (this Hash) CShake128(N, S []byte, num int) Hash {
    h := sha3.NewCShake128(N, S)
    h.Write(this.data)

    hash := make([]byte, num)
    h.Read(hash)

    this.data = hash

    return this
}

// CShake256 哈希值 num = 64
func (this Hash) CShake256(N, S []byte, num int) Hash {
    h := sha3.NewCShake256(N, S)
    h.Write(this.data)

    hash := make([]byte, num)
    h.Read(hash)

    this.data = hash

    return this
}
