package panama

import (
    "hash"
)

// New returns a new hash.Hash.
func New() hash.Hash {
    return newDigest()
}

// Sum returns the panama checksum of the data.
func Sum(data []byte) (out [Size]byte) {
    h := New()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}
