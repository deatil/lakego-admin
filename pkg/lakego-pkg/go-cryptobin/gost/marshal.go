package gost

import (
    "fmt"
    "errors"
)

// Marshal public key
func MarshalPublicKey(pub *PublicKey) []byte {
    pointSize := pub.Curve.PointSize()

    return append(
        BytesPadding(pub.X.Bytes(), pointSize),
        BytesPadding(pub.Y.Bytes(), pointSize)...,
    )
}

// Unmarshal public key
func UnmarshalPublicKey(c *Curve, raw []byte) (*PublicKey, error) {
    pointSize := c.PointSize()

    key := make([]byte, 2*pointSize)
    if len(raw) != len(key) {
        return nil, fmt.Errorf("gost: len(key)=%d != %d", len(key), pointSize)
    }

    return &PublicKey{
        c,
        BytesToBigint(raw[:pointSize]),
        BytesToBigint(raw[pointSize:]),
    }, nil
}

// ===============

// Marshal private key
func MarshalPrivateKey(priv *PrivateKey) (raw []byte) {
    return BytesPadding(priv.D.Bytes(), priv.Curve.PointSize())
}

// Unmarshal private key
func UnmarshalPrivateKey(c *Curve, raw []byte) (*PrivateKey, error) {
    pointSize := c.PointSize()
    if len(raw) != pointSize {
        return nil, fmt.Errorf("gost: len(key)=%d != %d", len(raw), pointSize)
    }

    k := BytesToBigint(raw)
    if k.Cmp(zero) == 0 {
        return nil, errors.New("gost: zero private key")
    }

    d := k.Mod(k, c.Q)

    x, y, err := c.Exp(d, c.X, c.Y)
    if err != nil {
        return nil, fmt.Errorf("gost: %w", err)
    }

    pub := PublicKey{
        Curve: c,
        X: x,
        Y: y,
    }

    return &PrivateKey{pub, d}, nil
}
