package hash

import (
    "github.com/deatil/go-hash/blake512"
)

// Blake512 hash
func (this Hash) Blake512() Hash {
    h := blake512.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewBlake512
func (this Hash) NewBlake512() Hash {
    this.hash = blake512.New()

    return this
}

// ===========

// Blake384 hash
func (this Hash) Blake384() Hash {
    h := blake512.New384()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewBlake384
func (this Hash) NewBlake384() Hash {
    this.hash = blake512.New384()

    return this
}
