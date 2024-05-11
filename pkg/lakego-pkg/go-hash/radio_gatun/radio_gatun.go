package radio_gatun

import (
    "hash"
)

// New32 returns a new hash.Hash computing the RadioGatun-32 checksum
func New32() hash.Hash {
    return newDigest32()
}

// New64 returns a new hash.Hash computing the RadioGatun-64 checksum
func New64() hash.Hash {
    return newDigest64()
}

// Sum32 returns the RadioGatun-32 checksum of the data.
func Sum32(data []byte) (out [Size32]byte) {
    h := New32()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum64 returns the RadioGatun-64 checksum of the data.
func Sum64(data []byte) (out [Size64]byte) {
    h := New64()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}
