package xxhash32

import "hash"

// New returns a new Hash32 instance.
func New() hash.Hash32 {
    return newDigest(0)
}

// NewWithSeed returns a new Hash32 instance.
func NewWithSeed(seed uint32) hash.Hash32 {
    return newDigest(seed)
}

// Checksum returns the 32bits Hash value.
func Sum(input []byte) (out [Size]byte) {
    sum := checksum(input, 0)
    putu32be(out[:], sum)

    return
}

// Checksum returns the 32bits Hash value.
func SumWithSeed(input []byte, seed uint32) (out [Size]byte) {
    sum := checksum(input, seed)
    putu32be(out[:], sum)

    return
}

// Checksum returns the 32bits Hash value.
func Checksum(input []byte) uint32 {
    return checksum(input, 0)
}

// ChecksumWithSeed returns the 32bits Hash value.
func ChecksumWithSeed(input []byte, seed uint32) uint32 {
    return checksum(input, seed)
}
