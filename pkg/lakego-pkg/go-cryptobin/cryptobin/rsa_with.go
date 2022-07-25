package cryptobin

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

// 设置 veryed
func (this Rsa) WithVeryed(data bool) Rsa {
    this.veryed = data

    return this
}

// 设置 hash 类型
func (this Rsa) WithSignHash(data string) Rsa {
    this.signHash = data

    return this
}

// 设置错误
func (this Rsa) WithError(err error) Rsa {
    this.Error = err

    return this
}
