package elgamal

import (
    "github.com/deatil/go-cryptobin/elgamal"
)

// 获取 PrivateKey
func (this EIGamal) GetPrivateKey() *elgamal.PrivateKey {
    return this.privateKey
}

// 获取 PublicKey
func (this EIGamal) GetPublicKey() *elgamal.PublicKey {
    return this.publicKey
}

// 获取 hash 类型
func (this EIGamal) GetSignHash() HashFunc {
    return this.signHash
}

// 获取 keyData
func (this EIGamal) GetKeyData() []byte {
    return this.keyData
}

// 获取 data
func (this EIGamal) GetData() []byte {
    return this.data
}

// 获取 parsedData
func (this EIGamal) GetParedData() []byte {
    return this.parsedData
}

// 获取验证后情况
func (this EIGamal) GetVerify() bool {
    return this.verify
}

// 获取错误
func (this EIGamal) GetErrors() []error {
    return this.Errors
}
