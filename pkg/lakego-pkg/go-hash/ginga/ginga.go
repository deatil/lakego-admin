package ginga

import (
    "hash"
)

// New returns a new hash.Hash.
func New() hash.Hash {
    return newDigest()
}

// Sum returns the ginga checksum of the data.
func Sum(data []byte) (out [Size]byte) {
    h := New()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}
