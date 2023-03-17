package hash

import (
    "github.com/deatil/go-hash/murmur3"
)

// murmur32
func (this Hash) Murmur32() Hash {
    h := murmur3.New32()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewMurmur32
func (this Hash) NewMurmur32() Hash {
    this.hash = murmur3.New32()

    return this
}

// murmur32
func (this Hash) Murmur32WithSeed(seed uint32) Hash {
    h := murmur3.New32WithSeed(seed)
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewMurmur32WithSeed
func (this Hash) NewMurmur32WithSeed(seed uint32) Hash {
    this.hash = murmur3.New32WithSeed(seed)

    return this
}

// ================

// murmur64
func (this Hash) Murmur64() Hash {
    h := murmur3.New64()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewMurmur64
func (this Hash) NewMurmur64() Hash {
    this.hash = murmur3.New64()

    return this
}

// murmur64
func (this Hash) Murmur64WithSeed(seed uint32) Hash {
    h := murmur3.New64WithSeed(seed)
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewMurmur64WithSeed
func (this Hash) NewMurmur64WithSeed(seed uint32) Hash {
    this.hash = murmur3.New64WithSeed(seed)

    return this
}

// ================

// murmur128
func (this Hash) Murmur128() Hash {
    h := murmur3.New128()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewMurmur128
func (this Hash) NewMurmur128() Hash {
    this.hash = murmur3.New128()

    return this
}

// murmur128
func (this Hash) Murmur128WithSeed(seed uint32) Hash {
    h := murmur3.New128WithSeed(seed)
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewMurmur128WithSeed
func (this Hash) NewMurmur128WithSeed(seed uint32) Hash {
    this.hash = murmur3.New128WithSeed(seed)

    return this
}
