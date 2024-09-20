package jh2

import (
    "hash"
)

// New224 returns a new hash.Hash computing the JH-224 checksum
func New224() hash.Hash {
    return newDigest(Size224, initVal224)
}

// Sum224 returns the JH-224 checksum of the data.
func Sum224(data []byte) (out [Size224]byte) {
    h := New224()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// ===========

// New256 returns a new hash.Hash computing the JH-256 checksum
func New256() hash.Hash {
    return newDigest(Size256, initVal256)
}

// Sum256 returns the JH-256 checksum of the data.
func Sum256(data []byte) (out [Size256]byte) {
    h := New256()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// ===========

// New384 returns a new hash.Hash computing the JH-384 checksum
func New384() hash.Hash {
    return newDigest(Size384, initVal384)
}

// Sum384 returns the JH-384 checksum of the data.
func Sum384(data []byte) (out [Size384]byte) {
    h := New384()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// ===========

// New512 returns a new hash.Hash computing the JH-512 checksum
func New512() hash.Hash {
    return newDigest(Size512, initVal512)
}

// Sum512 returns the JH-512 checksum of the data.
func Sum512(data []byte) (out [Size512]byte) {
    h := New512()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}
