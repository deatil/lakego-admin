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
        err := errors.New("EdDSA: privateKey error.")
        return this.AppendError(err)
    }

    var key any
    key = this.privateKey

    var ed25519Key crypto.Signer
    var ok bool

    if ed25519Key, ok = key.(crypto.Signer); !ok {
        err := errors.New("EdDSA: privateKey type error.")
        return this.AppendError(err)
    }

    if _, ok := ed25519Key.Public().(ed25519.PublicKey); !ok {
        err := errors.New("EdDSA: privateKey error.")
        return this.AppendError(err)
    }

    // 判断是否需要做 hash
    message := dataHash(this.data, this.options)

    sig, err := ed25519Key.Sign(rand.Reader, message, this.options)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = []byte(sig)

    return this
}

// 公钥验证
func (this EdDSA) Verify(data []byte) EdDSA {
    if this.publicKey == nil {
        err := errors.New("EdDSA: publicKey error.")
        return this.AppendError(err)
    }

    var key any
    key = this.publicKey

    var ed25519Key ed25519.PublicKey
    var ok bool

    if ed25519Key, ok = key.(ed25519.PublicKey); !ok {
        err := errors.New("EdDSA: publicKey type error.")
        return this.AppendError(err)
    }

    // 判断是否需要做 hash
    message := dataHash(data, this.options)

    err := ed25519.VerifyWithOptions(ed25519Key, message, this.data, this.options)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = true

    return this
}

// 判断是否需要做 hash
func dataHash(data []byte, opts *Options) []byte {
    hash := opts.HashFunc()

    if hash == crypto.SHA512 {
        h := hash.New()
        h.Write(data)

        return h.Sum(nil)
    }

    return data
}
