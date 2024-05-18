package gost

import (
    "fmt"
    "errors"
    "math/big"
    "crypto/cipher"

    cipher_gost "github.com/deatil/go-cryptobin/cipher/gost"
    "github.com/deatil/go-cryptobin/hash/gost/gost341194"
    "github.com/deatil/go-cryptobin/hash/gost/gost34112012256"
    "github.com/deatil/go-cryptobin/hash/gost/gost34112012512"
)

func NewUKM(raw []byte) *big.Int {
    t := make([]byte, len(raw))
    for i := 0; i < len(t); i++ {
        t[i] = raw[len(raw)-i-1]
    }

    return bigIntFromBytes(t)
}

func (prv *PrivateKey) KEK(pub *PublicKey, ukm *big.Int) ([]byte, error) {
    if pub == nil {
        return nil, fmt.Errorf("cryptobin/gost.KEK: PublicKey empty")
    }

    if !prv.Curve.Equal(pub.Curve) {
        return nil, fmt.Errorf("cryptobin/gost.KEK: PublicKey not same Curve")
    }

    keyX, keyY, err := prv.Curve.Exp(prv.D, pub.X, pub.Y)
    if err != nil {
        return nil, fmt.Errorf("cryptobin/gost.KEK: %w", err)
    }

    u := new(big.Int).Set(ukm).Mul(ukm, prv.Curve.Co)
    if u.Cmp(bigInt1) != 0 {
        keyX, keyY, err = prv.Curve.Exp(u, keyX, keyY)
        if err != nil {
            return nil, fmt.Errorf("cryptobin/gost.KEK: %w", err)
        }
    }

    return Marshal(prv.Curve, keyX, keyY), nil
}

func KEK(prv *PrivateKey, pub *PublicKey, ukm *big.Int) ([]byte, error) {
    if prv == nil {
        return nil, fmt.Errorf("cryptobin/gost.KEK: PrivateKey empty")
    }

    if pub == nil {
        return nil, fmt.Errorf("cryptobin/gost.KEK: PublicKey empty")
    }

    return prv.KEK(pub, ukm)
}

// RFC 4357 VKO GOST R 34.10-2001 key agreement function.
// UKM is user keying material, also called VKO-factor.
func (prv *PrivateKey) KEK2001(pub *PublicKey, ukm *big.Int) ([]byte, error) {
    if prv.Curve.PointSize() != 32 {
        return nil, errors.New("cryptobin/gost.KEK2001: KEK2001 is only for 256-bit curves")
    }

    key, err := prv.KEK(pub, ukm)
    if err != nil {
        return nil, fmt.Errorf("cryptobin/gost.KEK2001: %w", err)
    }

    h := gost341194.New(func(key []byte) cipher.Block {
        cip, _ := cipher_gost.NewCipher(key, cipher_gost.SboxGostR341194CryptoProParamSet)

        return cip
    })
    if _, err = h.Write(key); err != nil {
        return nil, fmt.Errorf("cryptobin/gost.KEK2001: %w", err)
    }

    return h.Sum(key[:0]), nil
}

func KEK2001(prv *PrivateKey, pub *PublicKey, ukm *big.Int) ([]byte, error) {
    if prv == nil {
        return nil, fmt.Errorf("cryptobin/gost.KEK2001: PrivateKey empty")
    }

    if pub == nil {
        return nil, fmt.Errorf("cryptobin/gost.KEK2001: PublicKey empty")
    }

    return prv.KEK2001(pub, ukm)
}

// RFC 7836 VKO GOST R 34.10-2012 256-bit key agreement function.
// UKM is user keying material, also called VKO-factor.
func (prv *PrivateKey) KEK2012256(pub *PublicKey, ukm *big.Int) ([]byte, error) {
    key, err := prv.KEK(pub, ukm)
    if err != nil {
        return nil, fmt.Errorf("cryptobin/gost.KEK2012256: %w", err)
    }

    h := gost34112012256.New()
    if _, err = h.Write(key); err != nil {
        return nil, fmt.Errorf("cryptobin/gost.KEK2012256: %w", err)
    }

    return h.Sum(key[:0]), nil
}

func KEK2012256(prv *PrivateKey, pub *PublicKey, ukm *big.Int) ([]byte, error) {
    if prv == nil {
        return nil, fmt.Errorf("cryptobin/gost.KEK2012256: PrivateKey empty")
    }

    if pub == nil {
        return nil, fmt.Errorf("cryptobin/gost.KEK2012256: PublicKey empty")
    }

    return prv.KEK2012256(pub, ukm)
}

// RFC 7836 VKO GOST R 34.10-2012 512-bit key agreement function.
// UKM is user keying material, also called VKO-factor.
func (prv *PrivateKey) KEK2012512(pub *PublicKey, ukm *big.Int) ([]byte, error) {
    key, err := prv.KEK(pub, ukm)
    if err != nil {
        return nil, fmt.Errorf("cryptobin/gost.KEK2012512: %w", err)
    }

    h := gost34112012512.New()
    if _, err = h.Write(key); err != nil {
        return nil, fmt.Errorf("cryptobin/gost.KEK2012512: %w", err)
    }

    return h.Sum(key[:0]), nil
}

func KEK2012512(prv *PrivateKey, pub *PublicKey, ukm *big.Int) ([]byte, error) {
    if prv == nil {
        return nil, fmt.Errorf("cryptobin/gost.KEK2012512: PrivateKey empty")
    }

    if pub == nil {
        return nil, fmt.Errorf("cryptobin/gost.KEK2012512: PublicKey empty")
    }

    return prv.KEK2012512(pub, ukm)
}
