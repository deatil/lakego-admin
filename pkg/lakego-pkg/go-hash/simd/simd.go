package simd

import (
    "hash"
)

// New224 returns a new hash.Hash computing the SIMD-224 checksum
func New224() hash.Hash {
    return newDigest256(Size224, iv224)
}

// New256 returns a new hash.Hash computing the SIMD-256 checksum
func New256() hash.Hash {
    return newDigest256(Size256, iv256)
}

// Sum224 returns the SIMD-224 checksum of the data.
func Sum224(data []byte) (out [Size224]byte) {
    h := New224()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum256 returns the SIMD-256 checksum of the data.
func Sum256(data []byte) (out [Size256]byte) {
    h := New256()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// ============

// New384 returns a new hash.Hash computing the SIMD-384 checksum
func New384() hash.Hash {
    return newDigest512(Size384, iv384)
}

// New512 returns a new hash.Hash computing the SIMD-512 checksum
func New512() hash.Hash {
    return newDigest512(Size512, iv512)
}

// Sum384 returns the SIMD-384 checksum of the data.
func Sum384(data []byte) (out [Size384]byte) {
    h := New384()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum512 returns the SIMD-512 checksum of the data.
func Sum512(data []byte) (out [Size512]byte) {
    h := New512()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}
