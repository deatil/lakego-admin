package cryptobin

import (
    "crypto/ecdsa"
)

// 获取 PrivateKey
func (this Ecdsa) GetPrivateKey() *ecdsa.PrivateKey {
    return this.privateKey
}

// 获取 PublicKey
func (this Ecdsa) GetPublicKey() *ecdsa.PublicKey {
    return this.publicKey
}

// 获取 keyData
func (this Ecdsa) GetKeyData() []byte {
    return this.keyData
}

// 获取 data
func (this Ecdsa) GetData() []byte {
    return this.data
}

// 获取 paredData
func (this Ecdsa) GetParedData() []byte {
    return this.paredData
}

// 获取 hash 类型
func (this Ecdsa) GetSignHash() string {
    return this.signHash
}

// 获取验证后情况
func (this Ecdsa) GetVeryed() bool {
    return this.veryed
}

// 获取错误
func (this Ecdsa) GetError() error {
    return this.Error
}
