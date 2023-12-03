package hash

import (
    "github.com/deatil/go-hash/lsh512"
)

// LSH512
func (this Hash) LSH512() Hash {
    h := lsh512.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewLSH512
func (this Hash) NewLSH512() Hash {
    this.hash = lsh512.New()

    return this
}

// ===========

// LSH512_384
func (this Hash) LSH512_384() Hash {
    h := lsh512.New384()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewLSH512_384
func (this Hash) NewLSH512_384() Hash {
    this.hash = lsh512.New384()

    return this
}

// ===========

// LSH512_256
func (this Hash) LSH512_256() Hash {
    h := lsh512.New256()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewLSH512_256
func (this Hash) NewLSH512_256() Hash {
    this.hash = lsh512.New256()

    return this
}

// ===========

// LSH512_224
func (this Hash) LSH512_224() Hash {
    h := lsh512.New224()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewLSH512_224
func (this Hash) NewLSH512_224() Hash {
    this.hash = lsh512.New224()

    return this
}
