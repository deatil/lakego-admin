package hash

import (
    "github.com/deatil/go-hash/siphash"
)

// Siphash64
func (this Hash) Siphash64(k []byte) Hash {
    h := siphash.New64(k)
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewSiphash64
func (this Hash) NewSiphash64(k []byte) Hash {
    this.hash = siphash.New64(k)

    return this
}

// ==============

// Siphash128
func (this Hash) Siphash128(k []byte) Hash {
    h := siphash.New128(k)
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewSiphash128
func (this Hash) NewSiphash128(k []byte) Hash {
    this.hash = siphash.New128(k)

    return this
}

// ==============

// SiphashWithCDroundsAndHashSize
func (this Hash) SiphashWithCDroundsAndHashSize(k []byte, crounds, drounds int32, hashSize int) Hash {
    h := siphash.NewWithCDroundsAndHashSize(k, crounds, drounds, hashSize)
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewSiphashWithCDroundsAndHashSize
func (this Hash) NewSiphashWithCDroundsAndHashSize(k []byte, crounds, drounds int32, hashSize int) Hash {
    this.hash = siphash.NewWithCDroundsAndHashSize(k, crounds, drounds, hashSize)

    return this
}
