package cubehash

import (
    "hash"
)

// NewCubehash returns a new hash.Hash.
func NewCubehash(hashSize, blockSize, r, ir, fr int) hash.Hash {
    return NewDigest(hashSize, blockSize, r, ir, fr)
}

// NewHS512x returns a new hash.Hash.
func NewHS512x() hash.Hash {
    return NewCubehash(512, 1, 16, 16, 32)
}

// NewHS512 returns a new hash.Hash.
func NewHS512() hash.Hash {
    return NewCubehash(512, 32, 16, 16, 32)
}

// NewHS384 returns a new hash.Hash.
func NewHS384() hash.Hash {
    return NewCubehash(384, 32, 16, 16, 32)
}

// NewHS256 returns a new hash.Hash.
func NewHS256() hash.Hash {
    return NewCubehash(256, 32, 16, 16, 32)
}

// NewHS224 returns a new hash.Hash.
func NewHS224() hash.Hash {
    return NewCubehash(224, 32, 16, 16, 32)
}

// NewHS192 returns a new hash.Hash.
func NewHS192() hash.Hash {
    return NewCubehash(192, 32, 16, 16, 32)
}

// NewHS160 returns a new hash.Hash.
func NewHS160() hash.Hash {
    return NewCubehash(160, 32, 16, 16, 32)
}

// NewHS128 returns a new hash.Hash.
func NewHS128() hash.Hash {
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

// SumHS512 returns the cubehash checksum of the data.
func SumHS512(data []byte) (out [Size]byte) {
    h := NewHS512()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// SumHS384 returns the cubehash checksum of the data.
func SumHS384(data []byte) (out [Size384]byte) {
    h := NewHS384()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// SumHS256 returns the cubehash checksum of the data.
func SumHS256(data []byte) (out [Size256]byte) {
    h := NewHS256()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// SumHS224 returns the cubehash checksum of the data.
func SumHS224(data []byte) (out [Size224]byte) {
    h := NewHS224()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// SumHS192 returns the cubehash checksum of the data.
func SumHS192(data []byte) (out [Size192]byte) {
    h := NewHS192()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// SumHS160 returns the cubehash checksum of the data.
func SumHS160(data []byte) (out [Size160]byte) {
    h := NewHS160()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// SumHS128 returns the cubehash checksum of the data.
func SumHS128(data []byte) (out [Size128]byte) {
    h := NewHS128()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// =======

// SumSH512 returns the cubehash checksum of the data.
func SumSH512(data []byte) (out [Size]byte) {
    h := NewSH512()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// SumSH256 returns the cubehash checksum of the data.
func SumSH256(data []byte) (out [Size256]byte) {
    h := NewSH256()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// SumSH224 returns the cubehash checksum of the data.
func SumSH224(data []byte) (out [Size224]byte) {
    h := NewSH224()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// SumSH192 returns the cubehash checksum of the data.
func SumSH192(data []byte) (out [Size192]byte) {
    h := NewSH192()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}
