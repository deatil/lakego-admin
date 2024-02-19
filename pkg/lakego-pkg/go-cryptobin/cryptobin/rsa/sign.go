package rsa

import (
    "errors"
    "crypto/rsa"
    "crypto/rand"
)

// 私钥签名
func (this RSA) Sign() RSA {
    if this.privateKey == nil {
        err := errors.New("rsa: privateKey error.")
        return this.AppendError(err)
    }

    h := this.signHash.New()
    h.Write(this.data)
    hashed := h.Sum(nil)

    parsedData, err := rsa.SignPKCS1v15(rand.Reader, this.privateKey, this.signHash, hashed)

    this.parsedData = parsedData

    return this.AppendError(err)
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this RSA) Verify(data []byte) RSA {
    if this.publicKey == nil {
        err := errors.New("rsa: publicKey error.")
        return this.AppendError(err)
    }

    h := this.signHash.New()
    h.Write(data)
    hashed := h.Sum(nil)

    err := rsa.VerifyPKCS1v15(this.publicKey, this.signHash, hashed, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = true

    return this
}
