package rsa

import (
    "crypto"
    "crypto/rsa"

    "github.com/deatil/go-cryptobin/tool"
)

// 设置 PrivateKey
func (this RSA) WithPrivateKey(data *rsa.PrivateKey) RSA {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this RSA) WithPublicKey(data *rsa.PublicKey) RSA {
    this.publicKey = data

    return this
}

// 设置 hash 类型
func (this RSA) WithSignHash(h crypto.Hash) RSA {
    this.signHash = h

    return this
}

// 设置 hash 类型
func (this RSA) SetSignHash(name string) RSA {
    hash, err := tool.GetCryptoHash(name)
    if err != nil {
        return this.AppendError(err)
    }

    this.signHash = hash

    return this
}

// 设置 data
func (this RSA) WithData(data []byte) RSA {
    this.data = data

    return this
}

// 设置 parsedData
func (this RSA) WithParedData(data []byte) RSA {
    this.parsedData = data

    return this
}

// 设置 verify
func (this RSA) WithVerify(data bool) RSA {
    this.verify = data

    return this
}

// 设置错误
func (this RSA) WithError(errs []error) RSA {
    this.Errors = errs

    return this
}
