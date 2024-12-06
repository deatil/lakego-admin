package rsa

import (
    "hash"
    "crypto"
    "crypto/rsa"
    "math/big"

    "github.com/deatil/go-cryptobin/tool/encoding"
)

// 获取 PrivateKey
func (this RSA) GetPrivateKey() *rsa.PrivateKey {
    return this.privateKey
}

// 获取 PublicKey
func (this RSA) GetPublicKey() *rsa.PublicKey {
    return this.publicKey
}

// 获取 PublicKeyN
func (this RSA) GetPublicKeyNString() string {
    data := this.publicKey.N

    return encoding.HexEncode(data.Bytes())
}

// 获取 PublicKeyE
func (this RSA) GetPublicKeyEString() string {
    e := big.NewInt(int64(this.publicKey.E))

    return encoding.HexEncode(e.Bytes())
}

// 获取 hash 类型
func (this RSA) GetSignHash() crypto.Hash {
    return this.signHash
}

// 获取 oaepHash 类型
func (this RSA) GetOAEPHash() hash.Hash {
    return this.oaepHash
}

// 获取 oaepLabel
func (this RSA) GetOAEPLabel() []byte {
    return this.oaepLabel
}

// 获取 keyData
func (this RSA) GetKeyData() []byte {
    return this.keyData
}

// 获取 data
func (this RSA) GetData() []byte {
    return this.data
}

// 获取 parsedData
func (this RSA) GetParsedData() []byte {
    return this.parsedData
}

// 获取验证后情况
func (this RSA) GetVerify() bool {
    return this.verify
}

// 获取错误
func (this RSA) GetErrors() []error {
    return this.Errors
}
