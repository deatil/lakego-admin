package ecdh

import (
    "crypto/ecdh"
)

// 获取 PrivateKey
func (this ECDH) GetPrivateKey() *ecdh.PrivateKey {
    return this.privateKey
}

// 获取 PublicKey
func (this ECDH) GetPublicKey() *ecdh.PublicKey {
    return this.publicKey
}

// 获取散列方式
func (this ECDH) GetCurve() ecdh.Curve {
    return this.curve
}

// 获取 keyData
func (this ECDH) GetKeyData() []byte {
    return this.keyData
}

// 获取 secretData
func (this ECDH) GetSecretData() []byte {
    return this.secretData
}

// 获取错误
func (this ECDH) GetErrors() []error {
    return this.Errors
}
