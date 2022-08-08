package dh

import (
    "github.com/deatil/go-cryptobin/dhd/dh"
)

// 设置 PrivateKey
func (this Dh) WithPrivateKey(data *dh.PrivateKey) Dh {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this Dh) WithPublicKey(data *dh.PublicKey) Dh {
    this.publicKey = data

    return this
}

// 设置 keyData
func (this Dh) WithKeyData(data []byte) Dh {
    this.keyData = data

    return this
}

// 设置错误
func (this Dh) WithError(err error) Dh {
    this.Error = err

    return this
}
