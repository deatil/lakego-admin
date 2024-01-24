package sm2

import (
    "github.com/deatil/go-cryptobin/gm/sm2/curve"
)

func Decompress(a []byte) *PublicKey {
    c := P256()

    x, y := curve.UnmarshalCompressed(c, a)

    return &PublicKey{
        Curve: c,
        X:     x,
        Y:     y,
    }
}

func Compress(a *PublicKey) []byte {
    return curve.MarshalCompressed(a.X, a.Y)
}
