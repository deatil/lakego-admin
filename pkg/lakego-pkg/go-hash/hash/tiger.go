package hash

import (
    "github.com/deatil/go-hash/tiger"
)

// Tiger
func (this Hash) Tiger() Hash {
    h := tiger.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewTiger
func (this Hash) NewTiger() Hash {
    this.hash = tiger.New()

    return this
}
