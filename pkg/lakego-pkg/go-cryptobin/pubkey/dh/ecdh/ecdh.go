package ecdh

import (
    "io"
    "errors"
    "math/big"
    "crypto"
    "crypto/elliptic"
    crypto_rand "crypto/rand"
)

type (
    Curve = elliptic.Curve
)

var (
    // 方式
    P521 = elliptic.P521
    P384 = elliptic.P384
    P256 = elliptic.P256
    P224 = elliptic.P224
)

// 公钥
type PublicKey struct {
    elliptic.Curve

    Y []byte
}

// 检测
func (this *PublicKey) Check() (err error) {
    x, y := unmarshal(this.Curve, this.Y)
    if !this.Curve.IsOnCurve(x, y) {
        err = errors.New("peer's public key is not on curve")
    }

    return
}

// 私钥
type PrivateKey struct {
    PublicKey

    X []byte
}

func (this *PrivateKey) Public() crypto.PublicKey {
    return &this.PublicKey
}

// 生成密码
func (this *PrivateKey) ComputeSecret(peersPublic *PublicKey) (secret []byte) {
    return ComputeSecret(this, peersPublic)
}

// 生成密钥对
func GenerateKey(curve elliptic.Curve, rand io.Reader) (*PrivateKey, *PublicKey, error) {
    if rand == nil {
        rand = crypto_rand.Reader
    }

    priv, x, y, err := elliptic.GenerateKey(curve, rand)
    if err != nil {
        return nil, nil, err
    }

    public := &PublicKey{}
    public.Y = elliptic.Marshal(curve, x, y)
    public.Curve = curve

    private := &PrivateKey{}
    private.X = priv
    private.PublicKey = *public

    return private, public, nil
}

// 从私钥获取公钥
func GeneratePublicKey(private *PrivateKey) (*PublicKey, error) {
    curve := private.Curve

    N := curve.Params().N

    if new(big.Int).SetBytes(private.X).Cmp(N) >= 0 {
        err := errors.New("ecdh: private key cannot used with given curve")
        return nil, err
    }

    x, y := curve.ScalarBaseMult(private.X)

    public := &PublicKey{}
    public.Y = elliptic.Marshal(curve, x, y)
    public.Curve = curve

    return public, nil
}

// 生成密码
func ComputeSecret(private *PrivateKey, peersPublic *PublicKey) (secret []byte) {
    x, y := unmarshal(private.Curve, peersPublic.Y)

    sX, _ := private.Curve.ScalarMult(x, y, private.X)

    secret = sX.Bytes()
    return
}

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

