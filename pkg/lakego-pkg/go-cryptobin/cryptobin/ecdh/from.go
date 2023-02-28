package ecdh

import (
    "crypto/rand"
    "crypto/ecdh"
)

// 私钥
func (this Ecdh) FromPrivateKey(key []byte) Ecdh {
    parsedKey, err := this.ParsePrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// 私钥带密码
func (this Ecdh) FromPrivateKeyWithPassword(key []byte, password string) Ecdh {
    parsedKey, err := this.ParsePrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = parsedKey.(*ecdh.PrivateKey)

    return this
}

// 公钥
func (this Ecdh) FromPublicKey(key []byte) Ecdh {
    parsedKey, err := this.ParsePublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = parsedKey.(*ecdh.PublicKey)

    return this
}

// 生成密钥
func (this Ecdh) GenerateKey() Ecdh {
    privateKey, err := this.curve.GenerateKey(rand.Reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.publicKey  = privateKey.PublicKey()

    return this
}
