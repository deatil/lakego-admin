package hash

import (
    "github.com/deatil/go-hash/lsh256"
)

// LSH256
func (this Hash) LSH256() Hash {
    h := lsh256.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewHAS160
func (this Hash) NewLSH256() Hash {
    this.hash = lsh256.New()

    return this
}

// ===========

// LSH256_224
func (this Hash) LSH256_224() Hash {
    h := lsh256.New224()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewLSH256_224
func (this Hash) NewLSH256_224() Hash {
    this.hash = lsh256.New224()

    return this
}
