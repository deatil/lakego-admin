package ecdh

import (
    "io"
    "hash"
    "errors"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/gm/sm2"
    "github.com/deatil/go-cryptobin/gm/sm2/sm2curve"
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

    size := (key.Curve.Params().N.BitLen() + 7) / 8
    if key.D.BitLen() > size*8 {
        return nil, errors.New("go-cryptobin/ecdh: invalid private key")
    }

    return c.NewPrivateKey(key.D.FillBytes(make([]byte, size)))
}

func (c *gmsm2Curve) NewPrivateKey(key []byte) (*PrivateKey, error) {
    if len(key) != 32 {
        return nil, errors.New("go-cryptobin/ecdh: invalid private key size")
    }

    if isZero(key) {
        return nil, errors.New("go-cryptobin/ecdh: invalid private key")
    }

    return &PrivateKey{
        NamedCurve: c,
        KeyBytes:   append([]byte{}, key...),
    }, nil
}

func (c *gmsm2Curve) PrivateKeyToPublicKey(key *PrivateKey) *PublicKey {
    if key.NamedCurve != c {
        panic("go-cryptobin/ecdh: converting the wrong key type")
    }

    curve := sm2.P256()

    x, y := curve.ScalarBaseMult(key.Bytes())

    publicKey := elliptic.Marshal(curve, x, y)
    if len(publicKey) == 1 {
        panic("go-cryptobin/ecdh: nistec ScalarBaseMult returned the identity")
    }

    k := &PublicKey{
        NamedCurve: key.NamedCurve,
        KeyBytes:   publicKey,
    }

    return k
}

func (c *gmsm2Curve) NewPublicKey(key []byte) (*PublicKey, error) {
    if len(key) == 0 || key[0] != 4 {
        return nil, errors.New("go-cryptobin/ecdh: invalid public key")
    }

    return &PublicKey{
        NamedCurve: c,
        KeyBytes:   append([]byte{}, key...),
    }, nil
}

func (c *gmsm2Curve) ECDH(local *PrivateKey, remote *PublicKey) ([]byte, error) {
    curve := sm2.P256()

    // 公钥
    xx, yy := elliptic.Unmarshal(curve, remote.Bytes())
    if xx == nil {
        return nil, errors.New("go-cryptobin/ecdh: failed to unmarshal elliptic curve point")
    }

    x, _ := curve.ScalarMult(xx, yy, local.Bytes())
    preMasterSecret := make([]byte, (curve.Params().BitSize+7)>>3)
    xBytes := x.Bytes()
    copy(preMasterSecret[len(preMasterSecret)-len(xBytes):], xBytes)

    return preMasterSecret, nil
}

func (c *gmsm2Curve) avf(secret *PublicKey) []byte {
    bytes := secret.KeyBytes[1:33]

    var result [32]byte
    copy(result[16:], bytes[16:])

    result[16] = (result[16] & 0x7f) | 0x80
    return result[:]
}

func (c *gmsm2Curve) ECMQV(sLocal, eLocal *PrivateKey, sRemote, eRemote *PublicKey) (*PublicKey, error) {
    // implicitSig: (sLocal + avf(eLocal.Pub) * ePriv) mod N
    x2 := c.avf(eLocal.PublicKey())
    t, err := sm2curve.ImplicitSig(sLocal.KeyBytes, eLocal.KeyBytes, x2)
    if err != nil {
        return nil, err
    }

    // new base point: peerPub + [x1](peerSecret)
    x1 := c.avf(eRemote)
    p2, err := sm2curve.NewPoint().SetBytes(eRemote.KeyBytes)
    if err != nil {
        return nil, err
    }

    if _, err := p2.ScalarMult(p2, x1); err != nil {
        return nil, err
    }

    p1, err := sm2curve.NewPoint().SetBytes(sRemote.KeyBytes)
    if err != nil {
        return nil, err
    }

    p2.Add(p1, p2)

    if _, err := p2.ScalarMult(p2, t); err != nil {
        return nil, err
    }

    return c.NewPublicKey(p2.Bytes())
}

// CalculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA).
// Compliance with GB/T 32918.2-2016 5.5
func (c *gmsm2Curve) SM2ZA(h func() hash.Hash, pub *PublicKey, uid []byte) ([]byte, error) {
    pubkey, err := sm2.NewPublicKey(pub.Bytes())
    if err != nil {
        return nil, err
    }

    return sm2.CalculateZALegacy(pubkey, h, uid)
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
    publicKey := elliptic.Marshal(sm2.P256(), pub.X, pub.Y)
    if len(publicKey) == 1 {
        return nil, errors.New("go-cryptobin/ecdh: sm2 PublicKey error")
    }

    return GmSM2().NewPublicKey(publicKey)
}

// 私钥导入为 ECDH 私钥
func SM2PrivateKeyToECDH(pri *sm2.PrivateKey) (*PrivateKey, error) {
    size := (pri.Curve.Params().N.BitLen() + 7) / 8
    if pri.D.BitLen() > size*8 {
        return nil, errors.New("go-cryptobin/ecdh: invalid private key")
    }

    key := pri.D.FillBytes(make([]byte, size))

    return GmSM2().NewPrivateKey(key)
}
