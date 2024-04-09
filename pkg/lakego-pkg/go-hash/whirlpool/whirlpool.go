package whirlpool

import (
    "hash"
)

// New returns a new hash.Hash computing the whirlpool checksum.
func New() hash.Hash {
    h := new(digest)
    h.Reset()

    return h
}

// Sum returns the whirlpool checksum of the data.
func Sum(data []byte) (out [Size]byte) {
    var h digest
    h.Reset()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}
