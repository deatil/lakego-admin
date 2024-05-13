package skeins

import (
    "hash"
)

// NewHS256 returns a new hash.Hash computing the Skein-HS224 checksum
func NewHS256(hs int, iv [4]uint64) hash.Hash {
    return newDigest256(hs, iv)
}

// ==============

// New224 returns a new hash.Hash computing the Skein-224 checksum
func New224() hash.Hash {
    return newDigest512(Size224, initVal224)
}

// New256 returns a new hash.Hash computing the Skein-256 checksum
func New256() hash.Hash {
    return newDigest512(Size256, initVal256)
}

// New384 returns a new hash.Hash computing the Skein-384 checksum
func New384() hash.Hash {
    return newDigest512(Size384, initVal384)
}

// New512 returns a new hash.Hash computing the Skein-512 checksum
func New512() hash.Hash {
    return newDigest512(Size512, initVal512)
}

// Sum224 returns the Skein-224 checksum of the data.
func Sum224(data []byte) (out [Size224]byte) {
    h := New224()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum256 returns the Skein-256 checksum of the data.
func Sum256(data []byte) (out [Size256]byte) {
    h := New256()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum384 returns the Skein-384 checksum of the data.
func Sum384(data []byte) (out [Size384]byte) {
    h := New384()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum512 returns the Skein-512 checksum of the data.
func Sum512(data []byte) (out [Size512]byte) {
    h := New512()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}
