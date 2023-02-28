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
        err := errors.New("EdDSA: [Sign()] privateKey error.")
        return this.AppendError(err)
    }

    var key any
    key = this.privateKey

    var ed25519Key crypto.Signer
    var ok bool

    if ed25519Key, ok = key.(crypto.Signer); !ok {
        err := errors.New("EdDSA: [Sign()] privateKey type error.")
        return this.AppendError(err)
    }

    if _, ok := ed25519Key.Public().(ed25519.PublicKey); !ok {
        err := errors.New("EdDSA: [Sign()] privateKey error.")
        return this.AppendError(err)
    }

    sig, err := ed25519Key.Sign(rand.Reader, this.data, crypto.Hash(0))
    if err != nil {
        return this.AppendError(err)
    }

    this.paredData = []byte(sig)

    return this
}

// 公钥验证
func (this EdDSA) Verify(data []byte) EdDSA {
    if this.publicKey == nil {
        err := errors.New("EdDSA: [Verify()] publicKey error.")
        return this.AppendError(err)
    }

    var key any
    key = this.publicKey

    var ed25519Key ed25519.PublicKey
    var ok bool

    if ed25519Key, ok = key.(ed25519.PublicKey); !ok {
        err := errors.New("EdDSA: [Verify()] publicKey type error.")
        return this.AppendError(err)
    }

    this.verify = ed25519.Verify(ed25519Key, data, this.data)

    return this
}
