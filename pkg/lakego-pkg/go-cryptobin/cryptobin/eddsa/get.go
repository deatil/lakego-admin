package eddsa

import (
    "crypto/ed25519"
)

// 获取 PrivateKey
func (this EdDSA) GetPrivateKey() ed25519.PrivateKey {
    return this.privateKey
}

// 获取 PrivateKeySeed
func (this EdDSA) GetPrivateKeySeed() []byte {
    return this.privateKey.Seed()
}

// 获取 PublicKey
func (this EdDSA) GetPublicKey() ed25519.PublicKey {
    return this.publicKey
}

// 获取 Options
func (this EdDSA) GetOptions() *Options {
    return this.options
}

// 获取 keyData
func (this EdDSA) GetKeyData() []byte {
    return this.keyData
}

// 获取 data
func (this EdDSA) GetData() []byte {
    return this.data
}

// 获取 paredData
func (this EdDSA) GetParedData() []byte {
    return this.paredData
}

// 获取验证后情况
func (this EdDSA) GetVerify() bool {
    return this.verify
}

// 获取错误
func (this EdDSA) GetErrors() []error {
    return this.Errors
}
