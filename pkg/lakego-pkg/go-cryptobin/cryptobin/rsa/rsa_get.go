package rsa

import (
    "crypto/rsa"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 获取 PrivateKey
func (this Rsa) GetPrivateKey() *rsa.PrivateKey {
    return this.privateKey
}

// 获取 PublicKey
func (this Rsa) GetPublicKey() *rsa.PublicKey {
    return this.publicKey
}

// 获取 PublicKeyN
func (this Rsa) GetPublicKeyNHexString() string {
    data := this.publicKey.N

    dataHex := cryptobin_tool.
        NewEncoding().
        HexEncode(data.Bytes())

    return dataHex
}

// 获取 PublicKeyE
func (this Rsa) GetPublicKeyE() int {
    return this.publicKey.E
}

// 获取 keyData
func (this Rsa) GetKeyData() []byte {
    return this.keyData
}

// 获取 data
func (this Rsa) GetData() []byte {
    return this.data
}

// 获取 paredData
func (this Rsa) GetParedData() []byte {
    return this.paredData
}

// 获取验证后情况
func (this Rsa) GetVerify() bool {
    return this.verify
}

// 获取 hash 类型
func (this Rsa) GetSignHash() string {
    return this.signHash
}

// 获取错误
func (this Rsa) GetErrors() []error {
    return this.Errors
}

// 获取错误
func (this Rsa) Error() *cryptobin_tool.Errors {
    return cryptobin_tool.NewError(this.Errors...)
}
