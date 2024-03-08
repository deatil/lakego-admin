package rsa

import (
    "errors"
    "math/big"
    "crypto/rsa"
)

// rsa no padding encrypt
func LowerSafeEncrypt(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
    if pub == nil {
        return nil, errors.New("cryptobin/rsa: incorrect public key")
    }

    m := new(big.Int).SetBytes(msg)

    e := big.NewInt(int64(pub.E))

    return new(big.Int).Exp(m, e, pub.N).Bytes(), nil
}

// rsa no padding decrypt
func LowerSafeDecrypt(priv *rsa.PrivateKey, msg []byte) ([]byte, error) {
    if priv == nil {
        return nil, errors.New("cryptobin/rsa: incorrect private key")
    }

    c := new(big.Int).SetBytes(msg)

    return new(big.Int).Exp(c, priv.D, priv.N).Bytes(), nil
}
