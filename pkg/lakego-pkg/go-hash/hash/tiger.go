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

// ===============


// Tiger
func (this Hash) Tiger2() Hash {
    h := tiger.New2()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewTiger
func (this Hash) NewTiger2() Hash {
    this.hash = tiger.New2()

    return this
}
