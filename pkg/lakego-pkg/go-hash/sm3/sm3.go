package sm3

import (
    "hash"
)

// New returns a new hash.Hash computing the SM3 checksum.
func New() hash.Hash {
    d := new(digest)
    d.Reset()
    return d
}

// Sum returns the SM3 checksum of the data.
func Sum(data []byte) (sum [Size]byte) {
    var h digest
    h.Reset()
    h.Write(data)

    hash := h.Sum(nil)
    copy(sum[:], hash)
    return
}
