package rsa

import (
    "crypto"
    "crypto/rsa"

    "github.com/deatil/go-cryptobin/tool"
)

// 设置 PrivateKey
func (this Rsa) WithPrivateKey(data *rsa.PrivateKey) Rsa {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this Rsa) WithPublicKey(data *rsa.PublicKey) Rsa {
    this.publicKey = data

    return this
}

// 设置 hash 类型
func (this Rsa) WithSignHash(h crypto.Hash) Rsa {
    this.signHash = h

    return this
}

// 设置 hash 类型
func (this Rsa) SetSignHash(data string) Rsa {
    hash, err := tool.GetCryptoHash(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.signHash = hash

    return this
}

// 设置 data
func (this Rsa) WithData(data []byte) Rsa {
    this.data = data

    return this
}

// 设置 paredData
func (this Rsa) WithParedData(data []byte) Rsa {
    this.paredData = data

    return this
}

// 设置 verify
func (this Rsa) WithVerify(data bool) Rsa {
    this.verify = data

    return this
}

// 设置错误
func (this Rsa) WithError(errs []error) Rsa {
    this.Errors = errs

    return this
}
