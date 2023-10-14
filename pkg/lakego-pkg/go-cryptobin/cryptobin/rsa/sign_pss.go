package rsa

import (
    "errors"
    "crypto/rsa"
    "crypto/rand"
)

// 私钥签名
// 常用为: PS256[SHA256] | PS384[SHA384] | PS512[SHA512]
func (this Rsa) SignPSS(opts ...rsa.PSSOptions) Rsa {
    if this.privateKey == nil {
        err := errors.New("Rsa: privateKey error.")
        return this.AppendError(err)
    }

    h := this.signHash.New()
    h.Write(this.data)
    hashed := h.Sum(nil)

    options := rsa.PSSOptions{
        SaltLength: rsa.PSSSaltLengthEqualsHash,
    }

    if len(opts) > 0 {
        options = opts[0]
    }

    paredData, err := rsa.SignPSS(rand.Reader, this.privateKey, this.signHash, hashed, &options)

    this.paredData = paredData

    return this.AppendError(err)
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this Rsa) VerifyPSS(data []byte, opts ...rsa.PSSOptions) Rsa {
    if this.publicKey == nil {
        err := errors.New("Rsa: publicKey error.")
        return this.AppendError(err)
    }

    h := this.signHash.New()
    h.Write(data)
    hashed := h.Sum(nil)

    options := rsa.PSSOptions{
        SaltLength: rsa.PSSSaltLengthAuto,
    }

    if len(opts) > 0 {
        options = opts[0]
    }

    err := rsa.VerifyPSS(this.publicKey, this.signHash, hashed, this.data, &options)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = true

    return this
}
