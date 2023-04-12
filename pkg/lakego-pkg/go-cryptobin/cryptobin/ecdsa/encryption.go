package ecdsa

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/ecc"
)

// 公钥加密
// Ecdsa 核心为对称加密
func (this Ecdsa) Encrypt() Ecdsa {
    if this.publicKey == nil {
        err := errors.New("Ecdsa: publicKey error.")
        return this.AppendError(err)
    }

    publicKey := ecc.ImportECDSAPublicKey(this.publicKey)

    paredData, err := ecc.Encrypt(rand.Reader, publicKey, this.data, nil, nil)
    if err != nil {
        return this.AppendError(err)
    }

    this.paredData = paredData

    return this
}

// 私钥解密
// Ecdsa 核心为对称加密
func (this Ecdsa) Decrypt() Ecdsa {
    if this.privateKey == nil {
        err := errors.New("Ecdsa: privateKey error.")
        return this.AppendError(err)
    }

    privateKey := ecc.ImportECDSAPrivateKey(this.privateKey)

    paredData, err := ecc.Decrypt(privateKey, this.data, nil, nil)
    if err != nil {
        return this.AppendError(err)
    }

    this.paredData = paredData

    return this
}
