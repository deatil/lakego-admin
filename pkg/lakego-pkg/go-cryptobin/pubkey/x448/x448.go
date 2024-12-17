// Package x448 implements the X448 Elliptic Curve Diffie-Hellman algorithm.
// See RFC 8032.
package x448

import (
    "io"
    "bytes"
    "errors"
    "strconv"
    "crypto"
    "crypto/subtle"
    cryptorand "crypto/rand"

    "github.com/deatil/go-cryptobin/elliptic/edwards448/field"
)

var basepoint []byte = []byte{
    5, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
}

const (
    // PublicKeySize is the size, in bytes, of public keys as used in this package.
    PublicKeySize = 56
    // PrivateKeySize is the size, in bytes, of private keys as used in this package.
    PrivateKeySize = 112
    // SignatureSize is the size, in bytes, of signatures generated and verified by this package.
    SignatureSize = 112
    // SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
    SeedSize = 56
)

// PublicKey is the type of X448 public keys.
type PublicKey []byte

// Equal reports whether pub and x have the same value.
func (pub PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(PublicKey)
    if !ok {
        return false
    }

    return bytes.Equal(pub, xx)
}

// PrivateKey is the type of X448 private keys.
type PrivateKey []byte

// Public returns the PublicKey corresponding to priv.
func (priv PrivateKey) Public() crypto.PublicKey {
    publicKey := make([]byte, PublicKeySize)
    copy(publicKey, priv[56:])
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
    copy(seed, priv[:56])
    return seed
}

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
    publicKey, err := X448(seed, basepoint)
    if err != nil {
        return nil, nil, err
    }
    copy(privateKey, seed)
    copy(privateKey[56:], publicKey)
    return publicKey, privateKey, nil
}

// NewKeyFromSeed calculates a private key from a seed. It will panic if
// len(seed) is not SeedSize. This function is provided for interoperability
// with RFC 8032. RFC 8032's private keys correspond to seeds in this
// package.
func NewKeyFromSeed(seed []byte) PrivateKey {
    if l := len(seed); l != SeedSize {
        panic("x448: bad seed length: " + strconv.Itoa(l))
    }

    privateKey := make([]byte, PrivateKeySize)
    publicKey, err := X448(seed, basepoint)
    if err != nil {
        panic(err)
    }

    copy(privateKey, seed)
    copy(privateKey[56:], publicKey)
    return privateKey
}

// X448 returns the result of the scalar multiplication (scalar * point),
// according to RFC 7748, Section 5. scalar, point and the return value are
// slices of 56 bytes.
func X448(scalar, point []byte) ([]byte, error) {
    if l := len(scalar); l != 56 {
        return nil, errors.New("x448: bad scalar length: " + strconv.Itoa(l) + ", expected 56")
    }
    if l := len(point); l != 56 {
        return nil, errors.New("x448: bad point length: " + strconv.Itoa(l) + ", expected 56")
    }

    var k [56]byte
    copy(k[:], scalar)
    k[0] &= 252
    k[55] |= 128

    var u field.Element
    u.SetBytes(point)

    var x1, x2, z2, x3, z3 field.Element
    x1.Set(&u)
    x2.One()
    x3.Set(&u)
    z3.One()
    swap := 0

    for t := 56*8 - 1; t >= 0; t-- {
        kt := int(k[t/8]>>(t%8)) & 1
        swap ^= kt
        x2.Swap(&x3, swap)
        z2.Swap(&z3, swap)
        swap = kt

        var a, aa, b, bb, e, c, d, da, cb field.Element
        a.Add(&x2, &z2)
        aa.Square(&a)
        b.Sub(&x2, &z2)
        bb.Square(&b)
        e.Sub(&aa, &bb)
        c.Add(&x3, &z3)
        d.Sub(&x3, &z3)
        da.Mul(&d, &a)
        cb.Mul(&c, &b)

        x3.Add(&da, &cb)
        x3.Square(&x3)

        z3.Sub(&da, &cb)
        z3.Square(&z3)
        z3.Mul(&z3, &x1)

        x2.Mul(&aa, &bb)

        z2.Mul32(&e, 39081)
        z2.Add(&z2, &aa)
        z2.Mul(&z2, &e)
    }

    x2.Swap(&x3, swap)
    z2.Swap(&z3, swap)

    var zero field.Element
    var ret field.Element
    ret.Mul(&x2, ret.Inv(&z2))
    if zero.Equal(&ret) == 1 {
        return nil, errors.New("x448 bad input point: low order point")
    }

    return ret.Bytes(), nil
}
