//go:build !go1.20

package x25519

import (
    cryptorand "crypto/rand"
    "io"

    "golang.org/x/crypto/curve25519"
)

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
    if rand == nil {
        rand = cryptorand.Reader
    }

    seed := make([]byte, SeedSize)
    if _, err := io.ReadFull(rand, seed); err != nil {
        return nil, nil, err
    }

    privateKey := make([]byte, PrivateKeySize)
    publicKey, err := curve25519.X25519(seed, curve25519.Basepoint)
    if err != nil {
        return nil, nil, err
    }
    copy(privateKey, seed)
    copy(privateKey[32:], publicKey)
    return publicKey, privateKey, nil
}

// NewKeyFromSeed calculates a private key from a seed. It will panic if
// len(seed) is not SeedSize. This function is provided for interoperability
// with RFC 8032. RFC 8032's private keys correspond to seeds in this
// package.
func NewKeyFromSeed(seed []byte) PrivateKey {
    return newKeyFromSeedLegacy(seed)
}

// X25519 returns the result of the scalar multiplication (scalar * point),
// according to RFC 7748, Section 5. scalar, point and the return value are slices of 32 bytes.
func X25519(scalar, point []byte) ([]byte, error) {
    return x25519Legacy(scalar, point)
}
