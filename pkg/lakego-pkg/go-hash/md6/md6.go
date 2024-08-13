package md6

import (
    "hash"
)

// New224 returns a new hash.Hash computing the MD6 checksum.
func New224() hash.Hash {
    return New(224)
}

// New256 returns a new hash.Hash computing the MD6 checksum.
func New256() hash.Hash {
    return New(256)
}

// New384 returns a new hash.Hash computing the MD6 checksum.
func New384() hash.Hash {
    return New(384)
}

// New512 returns a new hash.Hash computing the MD6 checksum.
func New512() hash.Hash {
    return New(512)
}

// New returns a new hash.Hash computing the MD6 checksum.
func New(size int) hash.Hash {
    return newDigest(size, nil, 64)
}

// NewWithKey returns a new hash.Hash computing the MD6 checksum.
func NewWithKey(size int, key []byte) hash.Hash {
    return newDigest(size, key, 64)
}

// NewMD6 returns a new hash.Hash computing the MD6 checksum.
func NewMD6(size int, key []byte, levels int) hash.Hash {
    return newDigest(size, key, levels)
}
