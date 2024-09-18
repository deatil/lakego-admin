package belt

import (
    "hash"
)

/*
 * This is an implementation of the BELT-HASH hash function as
 * defined int STB 34.101.31.
 */

// New returns a new hash.Hash computing the BELT checksum
func New() hash.Hash {
    return newDigest()
}

// Sum returns the BELT checksum of the data.
func Sum(data []byte) (sum [Size]byte) {
    h := New()
    h.Write(data)
    hashed := h.Sum(nil)

    copy(sum[:], hashed[:Size])
    return
}
