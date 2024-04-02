package siphash

import (
    "hash"
)

// New returns a new hash.Hash computing the Siphash checksum.
func New(k []byte) hash.Hash {
    h, _ := NewWithCDroundsAndHashSize(k, 0, 0, 0)
    return h
}

// return 8 bytes
func New64(k []byte) hash.Hash {
    h, _ := NewWithCDroundsAndHashSize(k, 0, 0, HashSize64)
    return h
}

// New alias, return 16 bytes
func New128(k []byte) hash.Hash {
    h, _ := NewWithCDroundsAndHashSize(k, 0, 0, HashSize128)
    return h
}

// NewWithHashSize returns a new hash.Hash computing the Siphash checksum.
func NewWithHashSize(k []byte, hashSize int) hash.Hash {
    h, _ := NewWithCDroundsAndHashSize(k, 0, 0, hashSize)
    return h
}

// NewWithCDroundsAndHashSize returns a new hash.Hash computing the Siphash checksum.
func NewWithCDroundsAndHashSize(k []byte, crounds, drounds int32, hashSize int) (hash.Hash, error) {
    return newDigest(k, crounds, drounds, hashSize)
}
