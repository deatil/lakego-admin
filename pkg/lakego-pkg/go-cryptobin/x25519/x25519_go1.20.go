//go:build go1.20

package x25519

import (
    "io"
    "crypto/ecdh"
    cryptorand "crypto/rand"
)

// ECDH returns pub as a [crypto/ecdh.PublicKey].
func (pub PublicKey) ECDH() (*ecdh.PublicKey, error) {
    c := ecdh.X25519()
    return c.NewPublicKey(pub)
}

// ECDH returns priv as a [crypto/ecdh.PrivateKey].
func (priv PrivateKey) ECDH() (*ecdh.PrivateKey, error) {
    c := ecdh.X25519()
    return c.NewPrivateKey(priv[:SeedSize])
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
    if rand == nil {
        rand = cryptorand.Reader
    }
    c := ecdh.X25519()
    priv, err := c.GenerateKey(rand)
    if err != nil {
        return nil, nil, err
    }
    pub := priv.PublicKey()

    pubBytes := pub.Bytes()
    privBytes := priv.Bytes()
    privBytes = append(privBytes, pubBytes...)

    return PublicKey(pubBytes), PrivateKey(privBytes), nil
}

// NewKeyFromSeed calculates a private key from a seed. It will panic if
// len(seed) is not SeedSize. This function is provided for interoperability
// with RFC 8032. RFC 8032's private keys correspond to seeds in this
// package.
func NewKeyFromSeed(seed []byte) PrivateKey {
    c := ecdh.X25519()
    priv, err := c.NewPrivateKey(seed)
    if err != nil {
        panic(err)
    }
    pub := priv.PublicKey()

    pubBytes := pub.Bytes()
    privBytes := priv.Bytes()
    privBytes = append(privBytes, pubBytes...)
    return PrivateKey(privBytes)
}

// X25519 returns the result of the scalar multiplication (scalar * point),
// according to RFC 7748, Section 5. scalar, point and the return value are slices of 32 bytes.
func X25519(scalar, point []byte) ([]byte, error) {
    c := ecdh.X25519()
    priv, err := c.NewPrivateKey(scalar)
    if err != nil {
        return nil, err
    }
    pub, err := c.NewPublicKey(point)
    if err != nil {
        return nil, err
    }
    return priv.ECDH(pub)
}
