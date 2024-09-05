package ecdsa

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/pubkey/ecc"
)

// 公钥加密
// ECDSA 核心为对称加密
func (this ECDSA) Encrypt() ECDSA {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    publicKey := ecc.ImportECDSAPublicKey(this.publicKey)

    parsedData, err := ecc.Encrypt(rand.Reader, publicKey, this.data, nil, nil)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 私钥解密
// ECDSA 核心为对称加密
func (this ECDSA) Decrypt() ECDSA {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    privateKey := ecc.ImportECDSAPrivateKey(this.privateKey)

    parsedData, err := ecc.Decrypt(privateKey, this.data, nil, nil)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}
