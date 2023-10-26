package ed448

import (
    "errors"
    "crypto"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/ed448"
)

// 私钥签名
func (this ED448) Sign() ED448 {
    if this.privateKey == nil {
        err := errors.New("ED448: privateKey error.")
        return this.AppendError(err)
    }

    var key any
    key = this.privateKey

    var ed448Key crypto.Signer
    var ok bool

    if ed448Key, ok = key.(crypto.Signer); !ok {
        err := errors.New("ED448: privateKey type error.")
        return this.AppendError(err)
    }

    if _, ok := ed448Key.Public().(ed448.PublicKey); !ok {
        err := errors.New("ED448: privateKey error.")
        return this.AppendError(err)
    }

    sig, err := ed448Key.Sign(rand.Reader, this.data, this.options)
    if err != nil {
        return this.AppendError(err)
    }

    this.paredData = []byte(sig)

    return this
}

// 公钥验证
func (this ED448) Verify(data []byte) ED448 {
    if this.publicKey == nil {
        err := errors.New("ED448: publicKey error.")
        return this.AppendError(err)
    }

    var key any
    key = this.publicKey

    var ed448Key ed448.PublicKey
    var ok bool

    if ed448Key, ok = key.(ed448.PublicKey); !ok {
        err := errors.New("ED448: publicKey type error.")
        return this.AppendError(err)
    }

    err := ed448.VerifyWithOptions(ed448Key, data, this.data, this.options)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = true

    return this
}
