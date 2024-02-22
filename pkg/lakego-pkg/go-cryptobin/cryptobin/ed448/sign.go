package ed448

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/ed448"
)

// 私钥签名
func (this ED448) Sign() ED448 {
    if this.privateKey == nil {
        err := errors.New("privateKey error.")
        return this.AppendError(err)
    }

    sig, err := this.privateKey.Sign(rand.Reader, this.data, this.options)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = []byte(sig)

    return this
}

// 公钥验证
func (this ED448) Verify(data []byte) ED448 {
    if this.publicKey == nil {
        err := errors.New("publicKey error.")
        return this.AppendError(err)
    }

    err := ed448.VerifyWithOptions(this.publicKey, data, this.data, this.options)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = true

    return this
}
