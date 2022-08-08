package ecdh

import (
    "github.com/deatil/go-cryptobin/dhd/ecdh"
)

// 设置 PrivateKey
func (this Ecdh) WithPrivateKey(data *ecdh.PrivateKey) Ecdh {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this Ecdh) WithPublicKey(data *ecdh.PublicKey) Ecdh {
    this.publicKey = data

    return this
}

// 设置 keyData
func (this Ecdh) WithKeyData(data []byte) Ecdh {
    this.keyData = data

    return this
}

// 设置错误
func (this Ecdh) WithError(err error) Ecdh {
    this.Error = err

    return this
}
