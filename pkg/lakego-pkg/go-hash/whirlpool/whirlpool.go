package whirlpool

import (
    "hash"
)

// New returns a new hash.Hash computing the Whirlpool checksum.
func New() hash.Hash {
    return newDigest(c, rc)
}

// Sum returns the Whirlpool checksum of the data.
func Sum(data []byte) (out [Size]byte) {
    h := New()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// ========

// New0 returns a new hash.Hash computing the Whirlpool-0 checksum.
func New0() hash.Hash {
    return newDigest(c0, rc0)
}

// Sum0 returns the Whirlpool-0 checksum of the data.
func Sum0(data []byte) (out [Size]byte) {
    h := New0()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// ========

// New1 returns a new hash.Hash computing the Whirlpool-1 checksum.
func New1() hash.Hash {
    return newDigest(c1, rc1)
}

// Sum1 returns the Whirlpool-1 checksum of the data.
func Sum1(data []byte) (out [Size]byte) {
    h := New1()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}
