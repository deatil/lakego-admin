package ecdsa

import (
    "math/big"
    "crypto/ecdsa"
    "crypto/elliptic"
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
// privateKeyXHex := cryptobin_tool.NewEncoding().HexEncode(GetPrivateKeyX().Bytes())
func (this Ecdsa) GetPrivateKeyX() *big.Int {
    return this.privateKey.X
}

// 获取 PrivateKeyY
// privateKeyYHex := cryptobin_tool.NewEncoding().HexEncode(GetPrivateKeyY().Bytes())
func (this Ecdsa) GetPrivateKeyY() *big.Int {
    return this.privateKey.Y
}

// 获取 PrivateKeyD
// privateKeyDHex := cryptobin_tool.NewEncoding().HexEncode(GetPrivateKeyD().Bytes())
func (this Ecdsa) GetPrivateKeyD() *big.Int {
    return this.privateKey.D
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
// publicKeyXHex := cryptobin_tool.NewEncoding().HexEncode(GetPublicKeyX().Bytes())
func (this Ecdsa) GetPublicKeyX() *big.Int {
    return this.publicKey.X
}

// 获取 PublicKeyY
// publicKeyYHex := cryptobin_tool.NewEncoding().HexEncode(GetPublicKeyY().Bytes())
func (this Ecdsa) GetPublicKeyY() *big.Int {
    return this.publicKey.Y
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
func (this Ecdsa) GetVeryed() bool {
    return this.veryed
}

// 获取错误
func (this Ecdsa) GetError() error {
    return this.Error
}
