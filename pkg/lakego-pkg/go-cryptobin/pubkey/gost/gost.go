package gost

import (
    "io"
    "fmt"
    "errors"
    "crypto"
    "math/big"
    "encoding/asn1"
)

// GOST R 34.10-2001 (RFC 5832),
// GOST R 34.10-2012 (RFC 7091) signature algorithms and
// VKO GOST R 34.10-2001 (RFC 4357),
// VKO GOST R 34.10-2012 (RFC 7836) key agreement algorithms.

// r and s data
type gostSignature struct {
    S, R *big.Int
}

// PublicKey represents an GOST public key.
type PublicKey struct {
    Curve *Curve
    X, Y  *big.Int
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*PublicKey)
    if !ok {
        return false
    }

    return pub.X.Cmp(xx.X) == 0 &&
        pub.Y.Cmp(xx.Y) == 0 &&
        pub.Curve.Equal(xx.Curve)
}

// Verify verifies the signature in hash using the public key, pub. It
// reports whether the signature is valid.
func (pub *PublicKey) Verify(digest, signature []byte) (bool, error) {
    pointSize := pub.Curve.PointSize()
    if len(signature) != 2*pointSize {
        return false, fmt.Errorf("go-cryptobin/gost: len(signature)=%d != %d", len(signature), 2*pointSize)
    }

    s := bigIntFromBytes(signature[:pointSize])
    r := bigIntFromBytes(signature[pointSize:])

    verify, err := VerifyWithRS(pub, digest, r, s)
    if err != nil {
        return false, errors.New("go-cryptobin/gost: " + err.Error())
    }

    return verify, nil
}

// Verify asn.1 signed data
func (pub *PublicKey) VerifyASN1(digest, signature []byte) (bool, error) {
    var sign gostSignature
    _, err := asn1.Unmarshal(signature, &sign)
    if err != nil {
        return false, err
    }

    verify, err := VerifyWithRS(pub, digest, sign.R, sign.S)
    if err != nil {
        return false, errors.New("go-cryptobin/gost: " + err.Error())
    }

    return verify, nil
}

// PrivateKey represents an GOST private key.
type PrivateKey struct {
    PublicKey
    D *big.Int
}

// Equal reports whether priv and x have the same value.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*PrivateKey)
    if !ok {
        return false
    }

    return priv.D.Cmp(xx.D) == 0 &&
        priv.PublicKey.Equal(&xx.PublicKey)
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
    return &priv.PublicKey
}

// Sign signs digest with priv, reading randomness from rand. The opts argument
// is not currently used but, in keeping with the crypto.Signer interface,
// should be the hash function used to digest the message.
// sig is s + r bytes
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
    r, s, err := SignToRS(rand, priv, digest)
    if err != nil {
        return nil, err
    }

    pointSize := priv.Curve.PointSize()

    signed := make([]byte, 2*pointSize)

    s.FillBytes(signed[        0:  pointSize])
    r.FillBytes(signed[pointSize:2*pointSize])

    return signed, nil
}

// Sign data to asn.1
func (priv *PrivateKey) SignASN1(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
    r, s, err := SignToRS(rand, priv, digest)
    if err != nil {
        return nil, err
    }

    signed, err := asn1.Marshal(gostSignature{
        R: r,
        S: s,
    })
    if err != nil {
        return nil, err
    }

    return signed, nil
}

func newPrivateKey(curve *Curve, raw []byte) (*PrivateKey, error) {
    k := bigIntFromBytes(raw)
    if k.Cmp(zero) == 0 {
        return nil, errors.New("go-cryptobin/gost: zero private key")
    }

    priv := new(PrivateKey)
    priv.D = k
    priv.PublicKey.Curve = curve
    priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(k.Bytes())

    return priv, nil
}

// GenerateKey generates a random GOST private key.
func GenerateKey(rand io.Reader, curve *Curve) (*PrivateKey, error) {
    private := make([]byte, curve.PointSize())
    if _, err := io.ReadFull(rand, private); err != nil {
        return nil, fmt.Errorf("go-cryptobin/gost: %w", err)
    }

    return newPrivateKey(curve, private)
}

// Unmarshal private key
func NewPrivateKey(curve *Curve, raw []byte) (*PrivateKey, error) {
    return newPrivateKey(curve, Reverse(raw))
}

// Marshal private key
func PrivateKeyTo(priv *PrivateKey) []byte {
    privateKey := make([]byte, priv.Curve.PointSize())
    priv.D.FillBytes(privateKey)

    return Reverse(privateKey)
}

// Unmarshal public key
func NewPublicKey(curve *Curve, data []byte) (*PublicKey, error) {
    x, y := Unmarshal(curve, data)
    if x == nil || y == nil {
        return nil, errors.New("go-cryptobin/gost: publicKey is incorrect.")
    }

    pub := &PublicKey{
        Curve: curve,
        X: x,
        Y: y,
    }

    return pub, nil
}

// Marshal public key
func PublicKeyTo(pub *PublicKey) []byte {
    return Marshal(pub.Curve, pub.X, pub.Y)
}

// Sign hash
func Sign(rand io.Reader, priv *PrivateKey, hash []byte) ([]byte, error) {
    if priv == nil {
        return nil, errors.New("go-cryptobin/gost: Private Key is error")
    }

    return priv.Sign(rand, hash, nil)
}

// Verify hash
func Verify(pub *PublicKey, hash, sig []byte) (bool, error) {
    if pub == nil {
        return false, errors.New("go-cryptobin/gost: Public Key is error")
    }

    return pub.Verify(hash, sig)
}

// SignASN1 signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the ASN.1 encoded signature.
func SignASN1(rand io.Reader, priv *PrivateKey, hash []byte) ([]byte, error) {
    if priv == nil {
        return nil, errors.New("go-cryptobin/gost: Private Key is error")
    }

    return priv.SignASN1(rand, hash, nil)
}

// VerifyASN1 verifies the ASN.1 encoded signature, sig, of hash using the
// public key, pub. Its return value records whether the signature is valid.
func VerifyASN1(pub *PublicKey, hash, sig []byte) (bool, error) {
    if pub == nil {
        return false, errors.New("go-cryptobin/gost: Public Key is error")
    }

    return pub.VerifyASN1(hash, sig)
}

// SignToRS
func SignToRS(rand io.Reader, priv *PrivateKey, digest []byte) (*big.Int, *big.Int, error) {
    digest = Reverse(digest)

    e := bigIntFromBytes(digest)

    e.Mod(e, priv.Curve.Q)
    if e.Cmp(zero) == 0 {
        e = big.NewInt(1)
    }

    kRaw := make([]byte, priv.Curve.PointSize())

    var err error
    var k *big.Int
    var r *big.Int

    d := big.NewInt(0)
    s := big.NewInt(0)

Retry:
    if _, err = io.ReadFull(rand, kRaw); err != nil {
        return nil, nil, fmt.Errorf("go-cryptobin/gost: %w", err)
    }

    k = bigIntFromBytes(kRaw)
    k.Mod(k, priv.Curve.Q)
    if k.Cmp(zero) == 0 {
        goto Retry
    }

    r, _ = priv.Curve.ScalarBaseMult(k.Bytes())

    r.Mod(r, priv.Curve.Q)
    if r.Cmp(zero) == 0 {
        goto Retry
    }

    d.Mul(priv.D, r)
    k.Mul(k, e)
    s.Add(d, k)
    s.Mod(s, priv.Curve.Q)
    if s.Cmp(zero) == 0 {
        goto Retry
    }

    return r, s, nil
}

// VerifyWithRS
func VerifyWithRS(pub *PublicKey, digest []byte, r, s *big.Int) (bool, error) {
    if r.Cmp(zero) <= 0 ||
        r.Cmp(pub.Curve.Q) >= 0 ||
        s.Cmp(zero) <= 0 ||
        s.Cmp(pub.Curve.Q) >= 0 {
        return false, nil
    }

    digest = Reverse(digest)

    e := bigIntFromBytes(digest)
    e.Mod(e, pub.Curve.Q)
    if e.Cmp(zero) == 0 {
        e = big.NewInt(1)
    }

    v := big.NewInt(0)
    v.ModInverse(e, pub.Curve.Q)

    z1 := big.NewInt(0)
    z2 := big.NewInt(0)

    z1.Mul(s, v)
    z1.Mod(z1, pub.Curve.Q)

    z2.Mul(r, v)
    z2.Mod(z2, pub.Curve.Q)
    z2.Sub(pub.Curve.Q, z2)

    p1x, p1y := pub.Curve.ScalarBaseMult(z1.Bytes())
    q1x, q1y := pub.Curve.ScalarMult(pub.X, pub.Y, z2.Bytes())

    lm := big.NewInt(0)
    lm.Sub(q1x, p1x)
    if lm.Cmp(zero) < 0 {
        lm.Add(lm, pub.Curve.P)
    }

    lm.ModInverse(lm, pub.Curve.P)

    z1.Sub(q1y, p1y)

    lm.Mul(lm, z1)
    lm.Mod(lm, pub.Curve.P)
    lm.Mul(lm, lm)
    lm.Mod(lm, pub.Curve.P)
    lm.Sub(lm, p1x)
    lm.Sub(lm, q1x)
    lm.Mod(lm, pub.Curve.P)
    if lm.Cmp(zero) < 0 {
        lm.Add(lm, pub.Curve.P)
    }

    lm.Mod(lm, pub.Curve.Q)

    return lm.Cmp(r) == 0, nil
}
