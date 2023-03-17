package hash

import (
    "hash"
    "hash/maphash"
)

// newMaphash
func newMaphash() hash.Hash64 {
    return &maphash.Hash{}
}

// Maphash
func (this Hash) Maphash() Hash {
    h := newMaphash()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewMaphash
func (this Hash) NewMaphash() Hash {
    this.hash = newMaphash()

    return this
}
