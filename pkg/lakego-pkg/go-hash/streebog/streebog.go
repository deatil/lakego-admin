package streebog

import (
    "hash"
)

// New256 returns a new hash.Hash computing the streebog checksum
func New256() hash.Hash {
    h, _ := New(256)
    return h
}

// New512 returns a new hash.Hash computing the streebog checksum
func New512() hash.Hash {
    h, _ := New(512)
    return h
}

// Sum256 returns the Streebog-256 checksum of the data.
func Sum256(data []byte) (sum256 [Size256]byte) {
    h := New256()
    h.Write(data)
    sum := h.Sum(nil)

    copy(sum256[:], sum[:Size256])
    return
}

// Sum512 returns the Streebog-512 checksum of the data.
func Sum512(data []byte) (sum512 [Size512]byte) {
    h := New512()
    h.Write(data)
    sum := h.Sum(nil)

    copy(sum512[:], sum[:Size512])
    return
}
