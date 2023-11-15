package rsa

import (
    "crypto"
    "crypto/rsa"
    "math/big"

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

    return cryptobin_tool.HexEncode(data.Bytes())
}

// 获取 PublicKeyE
func (this Rsa) GetPublicKeyEHexString() string {
    e := big.NewInt(int64(this.publicKey.E))

    return cryptobin_tool.HexEncode(e.Bytes())
}

// 获取 hash 类型
func (this Rsa) GetSignHash() crypto.Hash {
    return this.signHash
}

// 获取 keyData
func (this Rsa) GetKeyData() []byte {
    return this.keyData
}

// 获取 data
func (this Rsa) GetData() []byte {
    return this.data
}

// 获取 parsedData
func (this Rsa) GetParedData() []byte {
    return this.parsedData
}

// 获取验证后情况
func (this Rsa) GetVerify() bool {
    return this.verify
}

// 获取错误
func (this Rsa) GetErrors() []error {
    return this.Errors
}
