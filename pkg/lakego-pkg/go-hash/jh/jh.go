// Package jh implements JH-256 algorithm.
package jh

import (
    "hash"
)

// New returns a new hash.Hash computing the JH-256 checksum
func New() hash.Hash {
    return newDigest()
}

func Sum(data []byte) (sum [Size]byte) {
    var h digest
    h.Reset()
    h.Write(data)

    hash := h.Sum(nil)
    copy(sum[:], hash)
    return
}
