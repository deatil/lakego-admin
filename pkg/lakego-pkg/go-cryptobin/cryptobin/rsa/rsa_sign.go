package rsa

import (
    "errors"
    "crypto/rsa"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/tool"
)

// 私钥签名
func (this Rsa) Sign() Rsa {
    if this.privateKey == nil {
        err := errors.New("Rsa: [Sign()] privateKey error.")
        return this.AppendError(err)
    }

    newHash := tool.NewHash()

    hasher := newHash.GetCryptoHash(this.signHash)
    hashData := newHash.DataCryptoHash(this.signHash, this.data)

    paredData, err := rsa.SignPKCS1v15(rand.Reader, this.privateKey, hasher, hashData)

    this.paredData = paredData
    
    return this.AppendError(err)
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this Rsa) Verify(data []byte) Rsa {
    if this.publicKey == nil {
        err := errors.New("Rsa: [Verify()] publicKey error.")
        return this.AppendError(err)
    }

    newHash := tool.NewHash()

    hasher := newHash.GetCryptoHash(this.signHash)
    hashData := newHash.DataCryptoHash(this.signHash, data)

    err := rsa.VerifyPKCS1v15(this.publicKey, hasher, hashData, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = true

    return this
}
