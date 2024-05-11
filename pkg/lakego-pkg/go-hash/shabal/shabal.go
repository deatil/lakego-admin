package shabal

import (
    "hash"
)

// New returns a new hash.Hash computing the shabal checksum
func New(outSize int) (hash.Hash, error) {
    return newDigest(outSize)
}

// ============

// New192 returns a new hash.Hash computing the shabal-192 checksum
func New192() hash.Hash {
    h, _ := newDigest(192)
    return h
}

// Sum192 returns the shabal-192 checksum of the data.
func Sum192(data []byte) (out [Size192]byte) {
    h := New192()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// ============

// New224 returns a new hash.Hash computing the shabal-224 checksum
func New224() hash.Hash {
    h, _ := newDigest(224)
    return h
}

// Sum224 returns the shabal-224 checksum of the data.
func Sum224(data []byte) (out [Size224]byte) {
    h := New224()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// ============

// New256 returns a new hash.Hash computing the shabal-256 checksum
func New256() hash.Hash {
    h, _ := newDigest(256)
    return h
}

// Sum256 returns the shabal-256 checksum of the data.
func Sum256(data []byte) (out [Size256]byte) {
    h := New256()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// ============

// New384 returns a new hash.Hash computing the shabal-384 checksum
func New384() hash.Hash {
    h, _ := newDigest(384)
    return h
}

// Sum384 returns the shabal-384 checksum of the data.
func Sum384(data []byte) (out [Size384]byte) {
    h := New384()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// ============

// New512 returns a new hash.Hash computing the shabal-512 checksum
func New512() hash.Hash {
    h, _ := newDigest(512)
    return h
}

// Sum512 returns the shabal-512 checksum of the data.
func Sum512(data []byte) (out [Size512]byte) {
    h := New512()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}
