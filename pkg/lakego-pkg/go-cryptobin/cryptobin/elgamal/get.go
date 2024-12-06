package elgamal

import (
    "github.com/deatil/go-cryptobin/pubkey/elgamal"
)

// 获取 PrivateKey
func (this ElGamal) GetPrivateKey() *elgamal.PrivateKey {
    return this.privateKey
}

// 获取 PublicKey
func (this ElGamal) GetPublicKey() *elgamal.PublicKey {
    return this.publicKey
}

// 获取 hash 类型
func (this ElGamal) GetSignHash() HashFunc {
    return this.signHash
}

// 获取 keyData
func (this ElGamal) GetKeyData() []byte {
    return this.keyData
}

// 获取 data
func (this ElGamal) GetData() []byte {
    return this.data
}

// 获取 parsedData
func (this ElGamal) GetParsedData() []byte {
    return this.parsedData
}

// get Encoding type
func (this ElGamal) GetEncoding() EncodingType {
    return this.encoding
}

// 获取验证后情况
func (this ElGamal) GetVerify() bool {
    return this.verify
}

// 获取错误
func (this ElGamal) GetErrors() []error {
    return this.Errors
}
