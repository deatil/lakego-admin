package xxhash64

import "hash"

// New returns a new Hash64 instance.
func New() hash.Hash64 {
    return newDigest(0)
}

// NewWithSeed returns a new Hash64 instance.
func NewWithSeed(seed uint64) hash.Hash64 {
    return newDigest(seed)
}

// Checksum returns the 64bits Hash value.
func Sum(input []byte) (out [Size]byte) {
    sum := checksum(input, 0)
    putu64(out[:], sum)

    return
}

// Checksum returns the 64bits Hash value.
func SumWithSeed(input []byte, seed uint64) (out [Size]byte) {
    sum := checksum(input, seed)
    putu64(out[:], sum)

    return
}

// Checksum returns the 64bits Hash value.
func Checksum(input []byte) uint64 {
    return checksum(input, 0)
}

// ChecksumWithSeed returns the 64bits Hash value.
func ChecksumWithSeed(input []byte, seed uint64) uint64 {
    return checksum(input, seed)
}
