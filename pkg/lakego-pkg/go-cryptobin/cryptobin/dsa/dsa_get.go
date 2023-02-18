package dsa

import (
    "crypto/dsa"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 获取 PrivateKey
func (this DSA) GetPrivateKey() *dsa.PrivateKey {
    return this.privateKey
}

// 获取 PublicKey
func (this DSA) GetPublicKey() *dsa.PublicKey {
    return this.publicKey
}

// 获取 keyData
func (this DSA) GetKeyData() []byte {
    return this.keyData
}

// 获取 data
func (this DSA) GetData() []byte {
    return this.data
}

// 获取 paredData
func (this DSA) GetParedData() []byte {
    return this.paredData
}

// 获取 hash 类型
func (this DSA) GetSignHash() string {
    return this.signHash
}

// 获取验证后情况
func (this DSA) GetVerify() bool {
    return this.verify
}

// 获取错误
func (this DSA) GetErrors() []error {
    return this.Errors
}

// 获取错误
func (this DSA) Error() *cryptobin_tool.Errors {
    return cryptobin_tool.NewError(this.Errors...)
}
