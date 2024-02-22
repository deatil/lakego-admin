package ed448

import (
    "github.com/deatil/go-cryptobin/ed448"
)

// 获取 PrivateKey
func (this ED448) GetPrivateKey() ed448.PrivateKey {
    return this.privateKey
}

// 获取 PrivateKeySeed
func (this ED448) GetPrivateKeySeed() []byte {
    return this.privateKey.Seed()
}

// 获取 PublicKey
func (this ED448) GetPublicKey() ed448.PublicKey {
    return this.publicKey
}

// 获取 Options
func (this ED448) GetOptions() *Options {
    return this.options
}

// 获取 keyData
func (this ED448) GetKeyData() []byte {
    return this.keyData
}

// 获取 data
func (this ED448) GetData() []byte {
    return this.data
}

// 获取 parsedData
func (this ED448) GetParsedData() []byte {
    return this.parsedData
}

// 获取验证后情况
func (this ED448) GetVerify() bool {
    return this.verify
}

// 获取错误
func (this ED448) GetErrors() []error {
    return this.Errors
}
