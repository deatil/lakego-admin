package hash

import (
    "github.com/deatil/go-hash/siphash"
)

// Siphash
func (this Hash) Siphash(k []byte) Hash {
    h := siphash.New(k)
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewSiphash
func (this Hash) NewSiphash(k []byte) Hash {
    this.hash = siphash.New(k)

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
