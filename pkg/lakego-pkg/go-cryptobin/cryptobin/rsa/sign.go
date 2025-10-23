package rsa

import (
    "errors"
    "crypto"
    "crypto/rsa"
    "crypto/rand"
)

// 私钥签名
func (this RSA) Sign() RSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/rsa: privateKey empty.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData, err = rsa.SignPKCS1v15(rand.Reader, this.privateKey, this.signHash, hashed)

    return this.AppendError(err)
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this RSA) Verify(data []byte) RSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/rsa: publicKey empty.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(data)
    if err != nil {
        return this.AppendError(err)
    }

    err = rsa.VerifyPKCS1v15(this.publicKey, this.signHash, hashed, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = true

    return this
}

// 签名后数据
func (this RSA) dataHash(data []byte) ([]byte, error) {
    if this.signHash == crypto.Hash(0) {
        return nil, errors.New("go-cryptobin/rsa: signHash empty.")
    }

    h := this.signHash.New()
    h.Write(data)

    return h.Sum(nil), nil
}
