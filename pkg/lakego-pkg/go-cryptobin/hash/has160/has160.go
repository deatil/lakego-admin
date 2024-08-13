package has160

import (
    "hash"
)

// New returns a new hash.Hash computing the HAS-160 checksum.
func New() hash.Hash {
    return newDigest()
}

// Sum returns the HAS-160 checksum of the data.
func Sum(data []byte) (sum [Size]byte) {
    var h digest
    h.Reset()
    h.Write(data)

    hash := h.Sum(nil)
    copy(sum[:], hash)
    return
}
