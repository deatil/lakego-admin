package hash

import (
    "github.com/deatil/go-hash/blake256"
)

// Blake256 哈希值
func (this Hash) Blake256() Hash {
    h := blake256.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewBlake256
func (this Hash) NewBlake256() Hash {
    this.hash = blake256.New()

    return this
}

// ===========

// Blake256 哈希值
func (this Hash) Blake224() Hash {
    h := blake256.New224()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewBlake224
func (this Hash) NewBlake224() Hash {
    this.hash = blake256.New224()

    return this
}
