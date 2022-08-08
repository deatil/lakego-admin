package curve25519

import (
    "github.com/deatil/go-cryptobin/dhd/curve25519"
)

// 获取 PrivateKey
func (this Curve25519) GetPrivateKey() *curve25519.PrivateKey {
    return this.privateKey
}

// 获取 PublicKey
func (this Curve25519) GetPublicKey() *curve25519.PublicKey {
    return this.publicKey
}

// 获取 keyData
func (this Curve25519) GetKeyData() []byte {
    return this.keyData
}

// 获取错误
func (this Curve25519) GetError() error {
    return this.Error
}
