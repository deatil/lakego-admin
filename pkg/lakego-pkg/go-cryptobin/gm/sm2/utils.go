package sm2

import (
    "github.com/deatil/go-cryptobin/gm/sm2/curve"
)

// 解缩公钥
// Decompress PublicKey data
func Decompress(data []byte) *PublicKey {
    c := P256()

    x, y := curve.UnmarshalCompressed(c, data)

    return &PublicKey{
        Curve: c,
        X:     x,
        Y:     y,
    }
}

// 压缩公钥
// Compress PublicKey struct
func Compress(pub *PublicKey) []byte {
    return curve.MarshalCompressed(pub.Curve, pub.X, pub.Y)
}
