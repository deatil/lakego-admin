// Package x25519 implements the X25519 Elliptic Curve Diffie-Hellman algorithm.
// See RFC 8032.
package x25519

import (
    "bytes"
    "crypto"
    "crypto/subtle"
    "strconv"

    "golang.org/x/crypto/curve25519"
)

const (
    // PublicKeySize is the size, in bytes, of public keys as used in this package.
    PublicKeySize = 32
    // PrivateKeySize is the size, in bytes, of private keys as used in this package.
    PrivateKeySize = 64
    // SignatureSize is the size, in bytes, of signatures generated and verified by this package.
    SignatureSize = 64
    // SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
    SeedSize = 32
)

// PublicKey is the type of X25519 public keys.
type PublicKey []byte

// Any methods implemented on PublicKey might need to also be implemented on
// PrivateKey, as the latter embeds the former and will expose its methods.

// Equal reports whether pub and x have the same value.
func (pub PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(PublicKey)
    if !ok {
        return false
    }
    return bytes.Equal(pub, xx)
}

// PrivateKey is the type of X25519 private keys.
type PrivateKey []byte

// Public returns the PublicKey corresponding to priv.
func (priv PrivateKey) Public() crypto.PublicKey {
    publicKey := make([]byte, PublicKeySize)
    copy(publicKey, priv[32:])
    return PublicKey(publicKey)
}

// Equal reports whether priv and x have the same value.
func (priv PrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(PrivateKey)
    if !ok {
        return false
    }
    return subtle.ConstantTimeCompare(priv, xx) == 1
}

// Seed returns the private key seed corresponding to priv. It is provided for
// interoperability with RFC 8032. RFC 8032's private keys correspond to seeds
// in this package.
func (priv PrivateKey) Seed() []byte {
    seed := make([]byte, SeedSize)
    copy(seed, priv[:32])
    return seed
}

func newKeyFromSeedLegacy(seed []byte) PrivateKey {
    if l := len(seed); l != SeedSize {
        panic("x25519: bad seed length: " + strconv.Itoa(l))
    }

    privateKey := make([]byte, PrivateKeySize)
    publicKey, err := curve25519.X25519(seed, curve25519.Basepoint)
    if err != nil {
        panic(err)
    }
    copy(privateKey, seed)
    copy(privateKey[32:], publicKey)
    return privateKey
}

func x25519Legacy(scalar, point []byte) ([]byte, error) {
    return curve25519.X25519(scalar, point)
}
