package ecdh

import (
    "io"
    "errors"
    "crypto/elliptic"

    "github.com/tjfoc/gmsm/sm2"
)

// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
func GmSM2() Curve {
    return defaultGmSM2
}

var defaultGmSM2 = &gmsm2Curve{}

type gmsm2Curve struct{}

func (c *gmsm2Curve) String() string {
    return "GmSM2"
}

func (c *gmsm2Curve) GenerateKey(rand io.Reader) (*PrivateKey, error) {
    key, err := sm2.GenerateKey(rand)
    if err != nil {
        return nil, err
    }

    size := (sm2.P256Sm2().Params().N.BitLen() + 7) / 8
    if key.D.BitLen() > size*8 {
        return nil, errors.New("crypto/ecdh: invalid private key")
    }

    return c.NewPrivateKey(key.D.FillBytes(make([]byte, size)))
}

func (c *gmsm2Curve) NewPrivateKey(key []byte) (*PrivateKey, error) {
    if len(key) != 32 {
        return nil, errors.New("crypto/ecdh: invalid private key size")
    }

    if isZero(key) {
        return nil, errors.New("crypto/ecdh: invalid private key")
    }

    return &PrivateKey{
        NamedCurve: c,
        KeyBytes:   append([]byte{}, key...),
    }, nil
}

func (c *gmsm2Curve) PrivateKeyToPublicKey(key *PrivateKey) *PublicKey {
    if key.NamedCurve != c {
        panic("crypto/ecdh: converting the wrong key type")
    }

    curve := sm2.P256Sm2()

    x, y := curve.ScalarBaseMult(key.Bytes())

    publicKey := elliptic.Marshal(curve, x, y)
    if len(publicKey) == 1 {
        panic("crypto/ecdh: nistec ScalarBaseMult returned the identity")
    }

    k := &PublicKey{
        NamedCurve: key.NamedCurve,
        KeyBytes:   publicKey,
    }

    return k
}

func (c *gmsm2Curve) NewPublicKey(key []byte) (*PublicKey, error) {
    if len(key) == 0 || key[0] != 4 {
        return nil, errors.New("crypto/ecdh: invalid public key")
    }

    return &PublicKey{
        NamedCurve: c,
        KeyBytes:   append([]byte{}, key...),
    }, nil
}

func (c *gmsm2Curve) ECDH(local *PrivateKey, remote *PublicKey) ([]byte, error) {
    curve := sm2.P256Sm2()

    // 公钥
    xx, yy := elliptic.Unmarshal(curve, remote.Bytes())
    if xx == nil {
        return nil, errors.New("crypto/ecdh: failed to unmarshal elliptic curve point")
    }

    x, _ := curve.ScalarMult(xx, yy, local.Bytes())
    preMasterSecret := make([]byte, (curve.Params().BitSize+7)>>3)
    xBytes := x.Bytes()
    copy(preMasterSecret[len(preMasterSecret)-len(xBytes):], xBytes)

    return preMasterSecret, nil
}

func isZero(a []byte) bool {
    var acc byte
    for _, b := range a {
        acc |= b
    }

    return acc == 0
}

// 公钥导入为 ECDH 公钥
func SM2PublicKeyToECDH(pub *sm2.PublicKey) (*PublicKey, error) {
    publicKey := elliptic.Marshal(sm2.P256Sm2(), pub.X, pub.Y)
    if len(publicKey) == 1 {
        return nil, errors.New("crypto/ecdh: sm2 PublicKey error")
    }

    return GmSM2().NewPublicKey(publicKey)
}

// 私钥导入为 ECDH 私钥
func SM2PrivateKeyToECDH(pri *sm2.PrivateKey) (*PrivateKey, error) {
    size := (sm2.P256Sm2().Params().N.BitLen() + 7) / 8
    if pri.D.BitLen() > size*8 {
        return nil, errors.New("crypto/ecdh: invalid private key")
    }

    key := pri.D.FillBytes(make([]byte, size))

    return GmSM2().NewPrivateKey(key)
}
