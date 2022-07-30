package eddsa

import (
    "errors"
    "crypto"
    "crypto/rand"
    "crypto/ed25519"
)

// 私钥签名
func (this EdDSA) Sign() EdDSA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    var key any
    key = this.privateKey

    var ed25519Key crypto.Signer
    var ok bool

    if ed25519Key, ok = key.(crypto.Signer); !ok {
        this.Error = errors.New("私钥类型错误")
        return this
    }

    if _, ok := ed25519Key.Public().(ed25519.PublicKey); !ok {
        this.Error = errors.New("私钥错误")
        return this
    }

    sig, err := ed25519Key.Sign(rand.Reader, this.data, crypto.Hash(0))
    if err != nil {
        this.Error = err
        return this
    }

    this.paredData = []byte(sig)

    return this
}

// 公钥验证
func (this EdDSA) Very(data []byte) EdDSA {
    if this.publicKey == nil {
        this.Error = errors.New("publicKey error.")
        return this
    }

    var key any
    key = this.publicKey

    var ed25519Key ed25519.PublicKey
    var ok bool

    if ed25519Key, ok = key.(ed25519.PublicKey); !ok {
        this.Error = errors.New("公钥类型错误")
        return this
    }

    this.veryed = ed25519.Verify(ed25519Key, data, this.data)

    return this
}
