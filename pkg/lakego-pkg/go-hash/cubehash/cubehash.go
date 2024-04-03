package cubehash

import (
    "hash"
)

// NewCubehash returns a new hash.Hash.
func NewCubehash(hashSize, blockSize, r, ir, fr int) hash.Hash {
    return NewDigest(hashSize, blockSize, r, ir, fr)
}

// New returns a new hash.Hash.
func New() hash.Hash {
    return NewCubehash(512, 32, 16, 16, 32)
}

// New512x returns a new hash.Hash.
func New512x() hash.Hash {
    return NewCubehash(512, 1, 16, 16, 32)
}

// New384 returns a new hash.Hash.
func New384() hash.Hash {
    return NewCubehash(384, 32, 16, 16, 32)
}

// New256 returns a new hash.Hash.
func New256() hash.Hash {
    return NewCubehash(256, 32, 16, 16, 32)
}

// New224 returns a new hash.Hash.
func New224() hash.Hash {
    return NewCubehash(224, 32, 16, 16, 32)
}

// New192 returns a new hash.Hash.
func New192() hash.Hash {
    return NewCubehash(192, 32, 16, 16, 32)
}

// New160 returns a new hash.Hash.
func New160() hash.Hash {
    return NewCubehash(160, 32, 16, 16, 32)
}

// New128 returns a new hash.Hash.
func New128() hash.Hash {
    return NewCubehash(128, 32, 16, 16, 32)
}

// =======

// NewSH512 returns a new hash.Hash.
func NewSH512() hash.Hash {
    return NewCubehash(512, 32, 16, 160, 160)
}

// NewSH256 returns a new hash.Hash.
func NewSH256() hash.Hash {
    return NewCubehash(256, 32, 16, 160, 160)
}

// NewSH224 returns a new hash.Hash.
func NewSH224() hash.Hash {
    return NewCubehash(224, 32, 16, 160, 160)
}

// NewSH192 returns a new hash.Hash.
func NewSH192() hash.Hash {
    return NewCubehash(192, 32, 16, 160, 160)
}

// =======

// Sum returns the cubehash checksum of the data.
// Sum as Sum512
func Sum(data []byte) (out [Size]byte) {
    h := New()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum384 returns the cubehash checksum of the data.
func Sum384(data []byte) (out [Size384]byte) {
    h := New384()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum256 returns the cubehash checksum of the data.
func Sum256(data []byte) (out [Size256]byte) {
    h := New256()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum224 returns the cubehash checksum of the data.
func Sum224(data []byte) (out [Size224]byte) {
    h := New224()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum192 returns the cubehash checksum of the data.
func Sum192(data []byte) (out [Size192]byte) {
    h := New192()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum160 returns the cubehash checksum of the data.
func Sum160(data []byte) (out [Size160]byte) {
    h := New160()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum128 returns the cubehash checksum of the data.
func Sum128(data []byte) (out [Size128]byte) {
    h := New128()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}
