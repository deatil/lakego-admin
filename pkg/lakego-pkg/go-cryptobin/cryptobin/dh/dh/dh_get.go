package dh

import (
    "github.com/deatil/go-cryptobin/dhd/dh"
)

// 获取 PrivateKey
func (this Dh) GetPrivateKey() *dh.PrivateKey {
    return this.privateKey
}

// 获取 PublicKey
func (this Dh) GetPublicKey() *dh.PublicKey {
    return this.publicKey
}

// 获取 keyData
func (this Dh) GetKeyData() []byte {
    return this.keyData
}

// 获取错误
func (this Dh) GetError() error {
    return this.Error
}
