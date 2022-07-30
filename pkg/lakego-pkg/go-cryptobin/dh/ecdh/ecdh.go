package ecdh

import (
    "io"
    "errors"
    "math/big"
    "crypto/elliptic"
    cryptorand "crypto/rand"
)

// 公钥
type PublicKey []byte

// 私钥
type PrivateKey []byte

// 解出 x,y 数据
func unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
    byteLen := (curve.Params().BitSize + 7) >> 3
    if len(data) != 1+2*byteLen {
        return
    }

    if data[0] != 4 {
        return
    }

    x = new(big.Int).SetBytes(data[1 : 1+byteLen])
    y = new(big.Int).SetBytes(data[1+byteLen:])
    return
}

// ecdh
type Ecdh struct {
    curve elliptic.Curve
}

// 生成密钥对
func (this Ecdh) GenerateKey(rand io.Reader) (private PrivateKey, public PublicKey, err error) {
    if rand == nil {
        rand = cryptorand.Reader
    }

    private, x, y, err := elliptic.GenerateKey(this.curve, rand)
    if err != nil {
        private = nil
        return
    }

    public = elliptic.Marshal(this.curve, x, y)
    return
}

// 生成公钥
func (this Ecdh) PublicKey(private PrivateKey) (public PublicKey) {
    N := this.curve.Params().N

    if new(big.Int).SetBytes(private).Cmp(N) >= 0 {
        panic("ecdh: private key cannot used with given curve")
    }

    x, y := this.curve.ScalarBaseMult(private)
    public = elliptic.Marshal(this.curve, x, y)
    return
}

// 检测
func (this Ecdh) Check(peersPublic PublicKey) (err error) {
    x, y := unmarshal(this.curve, peersPublic)
    if !this.curve.IsOnCurve(x, y) {
        err = errors.New("peer's public key is not on curve")
    }

    return
}

// 生成密码
func (this Ecdh) ComputeSecret(private PrivateKey, peersPublic PublicKey) (secret []byte) {
    x, y := unmarshal(this.curve, peersPublic)

    sX, _ := this.curve.ScalarMult(x, y, private)

    secret = sX.Bytes()
    return
}

// 构造函数
// 可选 [P521 | P384 | P256 | P224]
func New(curve string) Ecdh {
    var c elliptic.Curve

    switch {
        case curve == "P521":
            c = elliptic.P521()
        case curve == "P384":
            c = elliptic.P384()
        case curve == "P256":
            c = elliptic.P256()
        case curve == "P224":
            c = elliptic.P224()
        default:
            c = elliptic.P256()
    }

    return Ecdh{curve: c}
}
