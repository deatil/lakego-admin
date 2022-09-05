package rsa

import (
    "crypto/rsa"
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

// 设置 hash 类型
func (this Rsa) WithSignHash(data string) Rsa {
    this.signHash = data

    return this
}

// 设置错误
func (this Rsa) WithError(errs []error) Rsa {
    this.Errors = errs

    return this
}

// 添加错误
func (this Rsa) AppendError(err ...error) Rsa {
    this.Errors = append(this.Errors, err...)

    return this
}
