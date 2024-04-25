package xxh3

import (
    "fmt"
    "hash"
)

// New64 returns a new hash.Hash64 computing the echo checksum
func New64() hash.Hash64 {
    return New64WithSeed(0)
}

// New64WithSecret returns a new hash.Hash64 computing the echo checksum
func New64WithSecret(secret []byte) (hash.Hash64, error) {
    if len(secret) < SECRET_SIZE_MIN {
        return nil, fmt.Errorf("secret too short")
    }

    return newDigest64(0, secret), nil
}

// New64WithSeed returns a new hash.Hash64 computing the echo checksum
func New64WithSeed(seed uint64) hash.Hash64 {
    secret := make([]byte, SECRET_DEFAULT_SIZE)
    GenCustomSecret(secret, seed)

    return newDigest64(seed, secret)
}

// Checksum returns the 64bits Hash value.
func Sum64(input []byte) (out [Size64]byte) {
    sum := checksum64(input, 0, kSecret)
    putu64be(out[:], sum)

    return
}

// Checksum returns the 64bits Hash value.
func Sum64WithSeed(input []byte, seed uint64) (out [Size64]byte) {
    sum := checksum64(input, seed, kSecret)
    putu64be(out[:], sum)

    return
}
