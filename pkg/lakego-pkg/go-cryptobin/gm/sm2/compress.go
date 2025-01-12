package sm2

import (
    "errors"

    "github.com/deatil/go-cryptobin/gm/sm2/sm2curve"
)

// 解缩公钥
// Decompress PublicKey data
func Decompress(data []byte) (*PublicKey, error) {
    c := P256()

    x, y := sm2curve.UnmarshalCompressed(c, data)
    if x == nil || y == nil {
        return nil, errors.New("go-cryptobin/sm2: compress publicKey is incorrect.")
    }

    pub := &PublicKey{
        Curve: c,
        X:     x,
        Y:     y,
    }

    return pub, nil
}

// 压缩公钥
// Compress PublicKey struct
func Compress(pub *PublicKey) []byte {
    return sm2curve.MarshalCompressed(pub.Curve, pub.X, pub.Y)
}
