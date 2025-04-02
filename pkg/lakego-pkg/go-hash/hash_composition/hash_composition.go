package hash_composition

import (
    "hash"
)

// New returns a new hash.Hash computing the hash_composition checksum
func New(h1, h2 func() hash.Hash) hash.Hash {
    return newDigest(h1, h2)
}

// Sum returns the hash_composition checksum of the data.
func Sum(h1, h2 func() hash.Hash, data []byte) (sum []byte) {
    h := New(h1, h2)
    h.Write(data)
    sum = h.Sum(nil)

    return
}
