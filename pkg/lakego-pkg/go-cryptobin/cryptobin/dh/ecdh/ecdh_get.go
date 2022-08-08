package ecdh

import (
    "github.com/deatil/go-cryptobin/dhd/ecdh"
)

// 获取 PrivateKey
func (this Ecdh) GetPrivateKey() *ecdh.PrivateKey {
    return this.privateKey
}

// 获取 PublicKey
func (this Ecdh) GetPublicKey() *ecdh.PublicKey {
    return this.publicKey
}

// 获取 keyData
func (this Ecdh) GetKeyData() []byte {
    return this.keyData
}

// 获取错误
func (this Ecdh) GetError() error {
    return this.Error
}
