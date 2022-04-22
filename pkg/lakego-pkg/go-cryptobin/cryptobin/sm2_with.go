package cryptobin

import (
    "github.com/tjfoc/gmsm/sm2"
)

// 设置 PrivateKey
func (this SM2) WithPrivateKey(data *sm2.PrivateKey) SM2 {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this SM2) WithPublicKey(data *sm2.PublicKey) SM2 {
    this.publicKey = data

    return this
}

// 设置 data
func (this SM2) WithData(data []byte) SM2 {
    this.data = data

    return this
}

// 设置 paredData
func (this SM2) WithParedData(data []byte) SM2 {
    this.paredData = data

    return this
}

// 设置错误
func (this SM2) WithError(err error) SM2 {
    this.Error = err

    return this
}
