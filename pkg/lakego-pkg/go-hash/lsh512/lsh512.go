package lsh512

import (
    "hash"
)

const (
    // The size of a LSH-512 checksum in bytes.
    Size = 64
    // The size of a LSH-512-224 checksum in bytes.
    Size224 = 28
    // The size of a LSH-512-256 checksum in bytes.
    Size256 = 32
    // The size of a LSH-384 checksum in bytes.
    Size384 = 48

    // The blocksize of LSH-512, LSH-384, LSH-512-256 and LSH-512-224 in bytes.
    BlockSize = 256
)

// New returns a new hash.Hash computing the LSH-512 checksum.
func New() hash.Hash {
    return newDigest(Size)
}

// New384 returns a new hash.Hash computing the LSH-384 checksum.
func New384() hash.Hash {
    return newDigest(Size384)
}

// New256 returns a new hash.Hash computing the LSH-512-256 checksum.
func New256() hash.Hash {
    return newDigest(Size256)
}

// New224 returns a new hash.Hash computing the LSH-512-224 checksum.
func New224() hash.Hash {
    return newDigest(Size224)
}

// Sum512 returns the LSH-512 checksum of the data.
func Sum512(data []byte) (sum512 [Size]byte) {
    b := New()
    b.Write(data)
    sum := b.Sum(nil)

    copy(sum512[:], sum)
    return
}

// Sum384 returns the LSH-384 checksum of the data.
func Sum384(data []byte) (sum384 [Size384]byte) {
    b := New()
    b.Write(data)
    sum := b.Sum(nil)

    copy(sum384[:], sum)
    return
}

// Sum256 returns the LSH-512-256 checksum of the data.
func Sum256(data []byte) (sum256 [Size256]byte) {
    b := New()
    b.Write(data)
    sum := b.Sum(nil)

    copy(sum256[:], sum)
    return
}

// Sum224 returns the LSH-512-224 checksum of the data.
func Sum224(data []byte) (sum224 [Size224]byte) {
    b := New()
    b.Write(data)
    sum := b.Sum(nil)

    copy(sum224[:], sum)
    return
}
