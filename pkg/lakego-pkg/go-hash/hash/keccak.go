package hash

import (
    "golang.org/x/crypto/sha3"
)

// Keccak256 哈希值
func (this Hash) Keccak256() Hash {
    h := sha3.NewLegacyKeccak256()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewKeccak256
func (this Hash) NewKeccak256() Hash {
    this.hash = sha3.NewLegacyKeccak256()

    return this
}

// ============================================

// Keccak512 哈希值
func (this Hash) Keccak512() Hash {
    h := sha3.NewLegacyKeccak512()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewKeccak512
func (this Hash) NewKeccak512() Hash {
    this.hash = sha3.NewLegacyKeccak512()

    return this
}
