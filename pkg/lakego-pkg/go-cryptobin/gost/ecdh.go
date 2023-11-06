package gost

import (
    "fmt"
    "math/big"
)

// default ukm bytes
var DefaultUkm = []byte("12345678")

// ECDH
func ECDH(priv *PrivateKey, pub *PublicKey) ([]byte, error) {
    return ECDHWithUkm(priv, pub, DefaultUkm)
}

// ECDHWithUkm
func ECDHWithUkm(priv *PrivateKey, pub *PublicKey, ukm []byte) ([]byte, error) {
    t := make([]byte, len(ukm))
    for i := 0; i < len(t); i++ {
        t[i] = ukm[len(ukm)-i-1]
    }

    ukmBigint := BytesToBigint(t)

    keyX, keyY, err := priv.Curve.Exp(priv.D, pub.X, pub.Y)
    if err != nil {
        return nil, fmt.Errorf("gost: %w", err)
    }

    u := big.NewInt(0).Set(ukmBigint).Mul(ukmBigint, priv.Curve.Co)
    if u.Cmp(bigInt1) != 0 {
        keyX, keyY, err = priv.Curve.Exp(u, keyX, keyY)
        if err != nil {
            return nil, fmt.Errorf("gost: %w", err)
        }
    }

    // use LE
    pointSize := priv.Curve.PointSize()

    raw := append(
        BytesPadding(keyY.Bytes(), pointSize),
        BytesPadding(keyX.Bytes(), pointSize)...,
    )

    Reverse(raw)

    return raw, nil
}
