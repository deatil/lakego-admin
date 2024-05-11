package sha0

import (
    "hash"
)

// New returns a new hash.Hash computing the sha0 checksum
func New() hash.Hash {
    return newDigest()
}

// Sum returns the sha0 checksum of the data.
func Sum(data []byte) (out [Size]byte) {
    h := New()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}
