package ecdh

import (
    "crypto/ecdh"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 获取 PrivateKey
func (this Ecdh) GetPrivateKey() *ecdh.PrivateKey {
    return this.privateKey
}

// 获取 PublicKey
func (this Ecdh) GetPublicKey() *ecdh.PublicKey {
    return this.publicKey
}

// 获取散列方式
func (this Ecdh) GetCurve() ecdh.Curve {
    return this.curve
}

// 获取 keyData
func (this Ecdh) GetKeyData() []byte {
    return this.keyData
}

// 获取 secretData
func (this Ecdh) GetSecretData() []byte {
    return this.secretData
}

// 获取错误
func (this Ecdh) GetErrors() []error {
    return this.Errors
}

// 获取错误
func (this Ecdh) Error() *cryptobin_tool.Errors {
    return cryptobin_tool.NewError(this.Errors...)
}
