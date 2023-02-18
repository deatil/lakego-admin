package ecdsa

import (
    "crypto/ecdsa"
    "crypto/elliptic"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 获取 PrivateKey
func (this Ecdsa) GetPrivateKey() *ecdsa.PrivateKey {
    return this.privateKey
}

// 获取 PrivateKeyCurve
func (this Ecdsa) GetPrivateKeyCurve() elliptic.Curve {
    return this.privateKey.Curve
}

// 获取 PrivateKeyX
func (this Ecdsa) GetPrivateKeyXHexString() string {
    data := this.privateKey.X

    dataHex := cryptobin_tool.
        NewEncoding().
        HexEncode(data.Bytes())

    return dataHex
}

// 获取 PrivateKeyY
func (this Ecdsa) GetPrivateKeyYHexString() string {
    data := this.privateKey.Y

    dataHex := cryptobin_tool.
        NewEncoding().
        HexEncode(data.Bytes())

    return dataHex
}

// 获取 PrivateKeyD
func (this Ecdsa) GetPrivateKeyDHexString() string {
    data := this.privateKey.D

    dataHex := cryptobin_tool.
        NewEncoding().
        HexEncode(data.Bytes())

    return dataHex
}

// 获取 PublicKey
func (this Ecdsa) GetPublicKey() *ecdsa.PublicKey {
    return this.publicKey
}

// 获取 PublicKeyCurve
func (this Ecdsa) GetPublicKeyCurve() elliptic.Curve {
    return this.publicKey.Curve
}

// 获取 PublicKeyX
func (this Ecdsa) GetPublicKeyXHexString() string {
    data := this.publicKey.X

    dataHex := cryptobin_tool.
        NewEncoding().
        HexEncode(data.Bytes())

    return dataHex
}

// 获取 PublicKeyY
func (this Ecdsa) GetPublicKeyYHexString() string {
    data := this.publicKey.Y

    dataHex := cryptobin_tool.
        NewEncoding().
        HexEncode(data.Bytes())

    return dataHex
}

// 获取 keyData
func (this Ecdsa) GetKeyData() []byte {
    return this.keyData
}

// 获取 data
func (this Ecdsa) GetData() []byte {
    return this.data
}

// 获取 paredData
func (this Ecdsa) GetParedData() []byte {
    return this.paredData
}

// 获取 hash 类型
func (this Ecdsa) GetSignHash() string {
    return this.signHash
}

// 获取验证后情况
func (this Ecdsa) GetVerify() bool {
    return this.verify
}

// 获取错误
func (this Ecdsa) GetErrors() []error {
    return this.Errors
}

// 获取错误
func (this Ecdsa) Error() *cryptobin_tool.Errors {
    return cryptobin_tool.NewError(this.Errors...)
}
