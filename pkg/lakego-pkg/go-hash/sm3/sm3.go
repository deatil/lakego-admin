package sm3

import (
    "hash"
)

// New returns a new hash.Hash computing the SM3 checksum.
func New() hash.Hash {
    return newDigest()
}

// Sum returns the SM3 checksum of the data.
func Sum(data []byte) (sum [Size]byte) {
    h := New()
    h.Write(data)
    hash := h.Sum(nil)

    copy(sum[:], hash)
    return
}
