package hamsi

import (
    "hash"
)

// New224 returns a new hash.Hash computing the hamsi-224 checksum
func New224() hash.Hash {
    return newDigest256(iv224, Size224)
}

// New256 returns a new hash.Hash computing the hamsi-256 checksum
func New256() hash.Hash {
    return newDigest256(iv256, Size256)
}

// New384 returns a new hash.Hash computing the hamsi-384 checksum
func New384() hash.Hash {
    return newDigest512(iv384, Size384)
}

// New512 returns a new hash.Hash computing the hamsi-512 checksum
func New512() hash.Hash {
    return newDigest512(iv512, Size512)
}

// Sum224 returns the hamsi-224 checksum of the data.
func Sum224(data []byte) (out [Size224]byte) {
    h := New224()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum256 returns the hamsi-256 checksum of the data.
func Sum256(data []byte) (out [Size256]byte) {
    h := New256()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum384 returns the hamsi-384 checksum of the data.
func Sum384(data []byte) (out [Size384]byte) {
    h := New384()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum512 returns the hamsi-512 checksum of the data.
func Sum512(data []byte) (out [Size512]byte) {
    h := New512()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}
