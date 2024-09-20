package fsb

import (
    "hash"
)

const (
    // hash size
    Size160 = 20
    Size224 = 28
    Size256 = 32
    Size384 = 48
    Size512 = 64
)

// New returns a new hash.Hash computing the FSB checksum
func New(hashbitlen int) (hash.Hash, error) {
    return newDigest(hashbitlen)
}

// Sum returns the FSB checksum of the data.
func Sum(data []byte, hashbitlen int) (sum []byte, err error) {
    h, err := New(hashbitlen)
    if err != nil {
        return
    }

    h.Write(data)
    hashed := h.Sum(nil)

    return hashed, nil
}

// ===========

// New160 returns a new hash.Hash computing the FSB checksum
func New160() hash.Hash {
    h, _ := New(160)
    return h
}

// Sum160 returns the FSB-160 checksum of the data.
func Sum160(data []byte) (sum160 [Size160]byte) {
    h := New160()
    h.Write(data)
    sum := h.Sum(nil)

    copy(sum160[:], sum[:Size160])
    return
}

// ===========

// New224 returns a new hash.Hash computing the FSB checksum
func New224() hash.Hash {
    h, _ := New(224)
    return h
}

// Sum224 returns the FSB-224 checksum of the data.
func Sum224(data []byte) (sum224 [Size224]byte) {
    h := New224()
    h.Write(data)
    sum := h.Sum(nil)

    copy(sum224[:], sum[:Size224])
    return
}

// ===========

// New256 returns a new hash.Hash computing the FSB checksum
func New256() hash.Hash {
    h, _ := New(256)
    return h
}

// Sum256 returns the FSB-256 checksum of the data.
func Sum256(data []byte) (sum256 [Size256]byte) {
    h := New256()
    h.Write(data)
    sum := h.Sum(nil)

    copy(sum256[:], sum[:Size256])
    return
}

// ===========

// New384 returns a new hash.Hash computing the FSB checksum
func New384() hash.Hash {
    h, _ := New(384)
    return h
}

// Sum384 returns the FSB-384 checksum of the data.
func Sum384(data []byte) (sum384 [Size384]byte) {
    h := New384()
    h.Write(data)
    sum := h.Sum(nil)

    copy(sum384[:], sum[:Size384])
    return
}

// ===========

// New512 returns a new hash.Hash computing the FSB checksum
func New512() hash.Hash {
    h, _ := New(512)
    return h
}

// Sum512 returns the FSB-512 checksum of the data.
func Sum512(data []byte) (sum512 [Size512]byte) {
    h := New512()
    h.Write(data)
    sum := h.Sum(nil)

    copy(sum512[:], sum[:Size512])
    return
}
