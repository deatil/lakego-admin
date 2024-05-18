package ripemd

import (
    "hash"
)

func New128() hash.Hash {
    return newDigest128()
}

// Sum128 returns checksum of the data.
func Sum128(data []byte) (sum [Size128]byte) {
    h := New128()
    h.Write(data)
    hash := h.Sum(nil)

    copy(sum[:], hash)
    return
}

// ============

// New160 returns a new hash.Hash computing the checksum.
func New160() hash.Hash {
    h := newDigest160()
    return h
}

// Sum160 returns checksum of the data.
func Sum160(data []byte) (sum [Size160]byte) {
    h := New160()
    h.Write(data)
    hash := h.Sum(nil)

    copy(sum[:], hash)
    return
}

// ============

func New256() hash.Hash {
    h := newDigest256()
    return h
}

// Sum256 returns checksum of the data.
func Sum256(data []byte) (sum [Size256]byte) {
    h := New256()
    h.Write(data)
    hash := h.Sum(nil)

    copy(sum[:], hash)
    return
}

// ============

func New320() hash.Hash {
    h := newDigest320()
    return h
}

// Sum320 returns checksum of the data.
func Sum320(data []byte) (sum [Size320]byte) {
    h := New320()
    h.Write(data)
    hash := h.Sum(nil)

    copy(sum[:], hash)
    return
}
