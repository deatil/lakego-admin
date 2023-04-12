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
        err := errors.New("Rsa: privateKey error.")
        return this.AppendError(err)
    }

    hash, err := tool.GetCryptoHash(this.signHash)
    if err != nil {
        return this.AppendError(err)
    }

    hashed, err := tool.CryptoHashSum(this.signHash, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    paredData, err := rsa.SignPKCS1v15(rand.Reader, this.privateKey, hash, hashed)

    this.paredData = paredData
    
    return this.AppendError(err)
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this Rsa) Verify(data []byte) Rsa {
    if this.publicKey == nil {
        err := errors.New("Rsa: publicKey error.")
        return this.AppendError(err)
    }

    hash, err := tool.GetCryptoHash(this.signHash)
    if err != nil {
        return this.AppendError(err)
    }

    hashed, err := tool.CryptoHashSum(this.signHash, data)
    if err != nil {
        return this.AppendError(err)
    }

    err = rsa.VerifyPKCS1v15(this.publicKey, hash, hashed, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = true

    return this
}
